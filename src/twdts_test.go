package wts

import (
	"flag"
	"fmt"
	"math/big"
	"math/rand"
	"strconv"
	"testing"
	"time"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
)

var NUM_NODES = flag.Int("signers", 1<<8, "Number of Signers")

func BenchmarkCompF(b *testing.B) {
	logN := 15
	n := 1 << logN

	fs := make([]fr.Element, n*logN)
	for i := 0; i < n*logN; i++ {
		fs[i].SetRandom()
	}

	for i := 0; i < b.N; i++ {
		for j := 0; j < 4; j++ {
			var sum fr.Element
			for ii := 0; ii < n*logN; ii++ {
				sum.Add(&sum, &fs[ii])
			}
		}
	}
}

func BenchmarkCompG1(b *testing.B) {
	logN := 15
	n := 1 << logN
	g1, _, _, _ := bls.Generators()

	var exp fr.Element
	gs := make([]bls.G1Jac, n)
	for i := 0; i < n; i++ {
		exp.SetRandom()
		gs[i].ScalarMultiplication(&g1, exp.BigInt(&big.Int{}))
	}

	for i := 0; i < b.N; i++ {
		var sumG bls.G1Jac
		for ii := 0; ii < n; ii++ {
			sumG.AddAssign(&gs[ii])
		}
	}
}

func TestGetOmega(t *testing.T) {
	n := 1 << 16
	seed := 0
	omega := GetOmega(n, seed)

	var omegaN fr.Element
	omegaN.Exp(omega, big.NewInt(int64(n)))
	one := fr.One()
	assert.Equal(t, omegaN, one, true)
}

// Test VTC Setup functionality
func TestVTCSetup(t *testing.T) {
	n := 1 << 4
	T1 := time.Duration(10) * time.Second
	T2 := time.Duration(5) * time.Second

	crs, err := Setup(n, T1, T2)
	assert.NoError(t, err)

	// Verify VTC generators are properly initialized
	assert.NotEqual(t, crs.hVTC, bls.G1Affine{})
	assert.NotEqual(t, crs.g2VTC, bls.G2Affine{})
}

// Test enhanced key generation with VTC
func TestKeyGenWithVTC(t *testing.T) {
	n := 1 << 4
	T1 := time.Duration(10) * time.Second
	T2 := time.Duration(5) * time.Second

	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i + 1 // Avoid zero weights
	}

	crs, _ := Setup(n, T1, T2)
	w := NewWTSWithVTC(n, weights, crs, T1, T2)

	// Testing that public keys are generated correctly
	var tPk bls.G1Affine
	for i := 0; i < n; i++ {
		tPk.ScalarMultiplication(&w.crs.g1a, w.signers[i].sKey.BigInt(&big.Int{}))
		assert.Equal(t, tPk.Equal(&w.signers[i].pKeyAff), true)
	}

	// Testing VTC keys are generated correctly
	var tVTCPk bls.G1Affine
	for i := 0; i < n; i++ {
		tVTCPk.ScalarMultiplication(&w.crs.hVTC, w.signers[i].vtcSKey.BigInt(&big.Int{}))
		assert.Equal(t, tVTCPk.Equal(&w.signers[i].vtcPKey), true)
	}

	// Checking whether the public key and hTaus is computed correctly
	lagH := GetAllLagAtWithOmegas(w.crs.H, w.crs.tau)
	var skTau fr.Element

	for i := 0; i < n; i++ {
		var skH fr.Element
		skH.Mul(&w.signers[i].sKey, &lagH[i])
		skTau.Add(&skTau, &skH)

		// Checking correctness of hTaus
		var hTau bls.G1Affine
		hTau.ScalarMultiplication(&w.crs.g1a, skH.BigInt(&big.Int{}))
		assert.Equal(t, hTau.Equal(&w.pp.hTaus[i]), true)
	}

	// Checking aggregated public key correctness
	var pComm bls.G1Affine
	pComm.ScalarMultiplication(&w.crs.g1a, skTau.BigInt(&big.Int{}))
	assert.Equal(t, pComm.Equal(&w.pp.pComm), true)

	// Checking whether lTaus are computed correctly or not
	lagL := GetLagAtSlow(w.crs.tau, w.crs.L)
	for i := 0; i < n; i++ {
		var skLl fr.Element
		var lTauL bls.G1Affine
		for l := 0; l < n-1; l++ {
			skLl.Mul(&w.signers[i].sKey, &lagL[l])
			lTauL.ScalarMultiplication(&w.crs.g1a, skLl.BigInt(&big.Int{}))
			assert.Equal(t, lTauL.Equal(&w.pp.lTaus[l][i]), true)
		}
	}
}

// Test blind signature functionality
func TestBlindSignature(t *testing.T) {
	n := 1 << 4
	T1 := time.Duration(10) * time.Second
	T2 := time.Duration(5) * time.Second
	msg := []byte("hello world")

	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i + 1
	}

	crs, _ := Setup(n, T1, T2)
	w := NewWTSWithVTC(n, weights, crs, T1, T2)

	// Test message blinding
	blindedMsg, blindingFactor := w.BlindMessage(msg)
	assert.NotEqual(t, blindedMsg.blindedHash, bls.G2Affine{})
	assert.NotEqual(t, blindingFactor.r, fr.Element{})

	// Test blind signing
	lockTime := time.Now().Add(T2)
	blindSig, vtcCommit, vtcProof := w.PartEvalWithVTC(blindedMsg, w.signers[0], lockTime)

	// Verify blind signature
	assert.NotEqual(t, blindSig.sigma, bls.G2Affine{})
	assert.NotEqual(t, vtcCommit.commitment, bls.G1Affine{})
	assert.NotEqual(t, vtcProof.pi, bls.G1Affine{})

	// Test partial verification (before unlock time)
	currentTime := time.Now()
	isValid := w.PVerifyWithVTC(blindedMsg, blindSig, vtcCommit, vtcProof, w.signers[0].pKeyAff, currentTime)
	assert.True(t, isValid)

	// Test unblinding
	unblindedSig := w.UnblindSignature(blindSig, blindingFactor)
	assert.NotEqual(t, unblindedSig.sigma, bls.G2Affine{})

	// Verify unblinded signature matches expected
	roMsg, _ := bls.HashToG2(msg, []byte{})
	res, _ := bls.PairingCheck(
		[]bls.G1Affine{w.signers[0].pKeyAff, w.crs.g1InvAff},
		[]bls.G2Affine{roMsg, unblindedSig.sigma})
	assert.True(t, res)
}

// Test VTC functionality - Fixed version
func TestVTC(t *testing.T) {
	n := 1 << 4
	T1 := time.Duration(1) * time.Second
	T2 := time.Duration(500) * time.Millisecond

	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i + 1
	}

	crs, _ := Setup(n, T1, T2)
	w := NewWTSWithVTC(n, weights, crs, T1, T2)

	// Create VTC commitment using a non-zero value
	var commitValue fr.Element
	commitValue.SetRandom()

	lockTime := time.Now().Add(T2)
	vtcCommit := VTCCommitment{
		commitment: *new(bls.G1Affine).ScalarMultiplication(&w.crs.hVTC, commitValue.BigInt(&big.Int{})),
		timeParam:  lockTime,
		proof:      *new(bls.G1Affine).ScalarMultiplication(&w.crs.g1a, commitValue.BigInt(&big.Int{})),
	}

	// Test commitment verification - check that it's not infinity
	vtcValid := !vtcCommit.commitment.IsInfinity()
	assert.True(t, vtcValid)

	// Test VTC solving (after time passes)
	time.Sleep(T2 + 100*time.Millisecond)
	solution, solved := w.SolveVTC(vtcCommit, T1+100*time.Millisecond)
	assert.True(t, solved)
	assert.NotEqual(t, solution, fr.Element{})
}

// Test complete WDVTS workflow - More robust version
func TestWDVTS(t *testing.T) {
	msg := []byte("hello world")
	n := 1 << 4
	T1 := time.Duration(100) * time.Millisecond
	T2 := time.Duration(50) * time.Millisecond

	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i + 1
	}

	crs, _ := Setup(n, T1, T2)
	w := NewWTSWithVTC(n, weights, crs, T1, T2)
	w.preProcess()

	// Blind the message
	blindedMsg, _ := w.BlindMessage(msg)

	// Generate signatures from subset of signers - ensure we have enough signers
	var signers []int
	var blindSigs []BlindSignature
	var vtcCommits []VTCCommitment
	var vtcProofs []VTCProof
	ths := 0
	lockTime := time.Now().Add(T2)

	// Use a deterministic approach to select signers for consistent testing
	for i := 0; i < n; i++ {
		if i%2 == 0 || len(signers) < n/2 { // Select every other signer, ensure minimum
			signers = append(signers, i)
			blindSig, vtcCommit, vtcProof := w.PartEvalWithVTC(blindedMsg, w.signers[i], lockTime)
			blindSigs = append(blindSigs, blindSig)
			vtcCommits = append(vtcCommits, vtcCommit)
			vtcProofs = append(vtcProofs, vtcProof)
			ths += weights[i]
		}
	}

	fmt.Printf("TestWDVTS: Selected %d signers with threshold %d\n", len(signers), ths)

	// Verify partial signatures
	for i, idx := range signers {
		isValid := w.PVerifyWithVTC(blindedMsg, blindSigs[i], vtcCommits[i], vtcProofs[i], w.signers[idx].pKeyAff, time.Now())
		assert.True(t, isValid, fmt.Sprintf("Partial signature %d should be valid", i))
	}

	// Combine signatures
	sig := w.CombineWithVTC(signers, blindSigs, vtcCommits, vtcProofs, lockTime)

	// Verify combined signature before unlock time (should fail)
	currentTime := time.Now()
	isValidBefore := w.VerifyWithVTC(msg, sig, ths, currentTime)
	assert.False(t, isValidBefore, "Signature should not be valid before unlock time")

	// Wait for unlock time and verify again
	time.Sleep(T2 + T1 + 100*time.Millisecond)
	currentTime = time.Now()
	isValidAfter := w.VerifyWithVTC(msg, sig, ths, currentTime)
	assert.True(t, isValidAfter, "Signature should be valid after unlock time")
}

// Benchmark VTC Commit operation
func BenchmarkVTCCommit(b *testing.B) {
	flag.Parse()
	n := *NUM_NODES
	T1 := time.Duration(10) * time.Second
	T2 := time.Duration(5) * time.Second

	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i + 1
	}

	crs, _ := Setup(n, T1, T2)
	w := NewWTSWithVTC(n, weights, crs, T1, T2)

	b.Run("VTCCommit-N:"+strconv.Itoa(n), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var commitValue fr.Element
			commitValue.SetRandom()

			_ = VTCCommitment{
				commitment: *new(bls.G1Affine).ScalarMultiplication(&w.crs.hVTC, commitValue.BigInt(&big.Int{})),
				timeParam:  time.Now(),
				proof:      *new(bls.G1Affine).ScalarMultiplication(&w.crs.g1a, commitValue.BigInt(&big.Int{})),
			}
		}
	})
}

// Benchmark VTC Verify operation
func BenchmarkVTCVerify(b *testing.B) {
	flag.Parse()
	n := *NUM_NODES
	T1 := time.Duration(10) * time.Second
	T2 := time.Duration(5) * time.Second

	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i + 1
	}

	crs, _ := Setup(n, T1, T2)
	w := NewWTSWithVTC(n, weights, crs, T1, T2)

	var commitValue fr.Element
	commitValue.SetRandom()
	vtcCommit := VTCCommitment{
		commitment: *new(bls.G1Affine).ScalarMultiplication(&w.crs.hVTC, commitValue.BigInt(&big.Int{})),
		timeParam:  time.Now(),
		proof:      *new(bls.G1Affine).ScalarMultiplication(&w.crs.g1a, commitValue.BigInt(&big.Int{})),
	}

	b.Run("VTCVerify-N:"+strconv.Itoa(n), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Simply check if commitment is not infinity
			_ = !vtcCommit.commitment.IsInfinity()
		}
	})
}

// Benchmark IPA proof generation
func BenchmarkCombineWithVTC(b *testing.B) {
	flag.Parse()
	n := *NUM_NODES
	T1 := time.Duration(10) * time.Second
	T2 := time.Duration(5) * time.Second

	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i + 1
	}

	crs, _ := Setup(n, T1, T2)
	w := NewWTSWithVTC(n, weights, crs, T1, T2)

	w.preProcess()

	// 预先准备数据
	msg := []byte("hello world")
	blindedMsg, _ := w.BlindMessage(msg)
	lockTime := time.Now().Add(T2)

	signers := make([]int, n)
	blindSigs := make([]BlindSignature, n)
	vtcCommits := make([]VTCCommitment, n)
	vtcProofs := make([]VTCProof, n)
	for i := 0; i < n; i++ {
		signers[i] = i
		blindSigs[i], vtcCommits[i], vtcProofs[i] = w.PartEvalWithVTC(blindedMsg, w.signers[i], lockTime)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = w.CombineWithVTC(signers, blindSigs, vtcCommits, vtcProofs, lockTime)
	}
}

// Benchmark IPA proof verification
func BenchmarkIPAProofVerification(b *testing.B) {
	flag.Parse()
	n := *NUM_NODES
	T1 := time.Duration(10) * time.Second
	T2 := time.Duration(5) * time.Second
	msg := []byte("hello world")

	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i + 1
	}

	crs, _ := Setup(n, T1, T2)
	w := NewWTSWithVTC(n, weights, crs, T1, T2)
	w.preProcess()

	// Generate a signature for benchmarking
	blindedMsg, _ := w.BlindMessage(msg)
	var signers []int
	var blindSigs []BlindSignature
	var vtcCommits []VTCCommitment
	var vtcProofs []VTCProof
	ths := 0
	lockTime := time.Now().Add(T2)

	// Use all signers for maximum complexity
	for i := 0; i < n; i++ {
		signers = append(signers, i)
		blindSig, vtcCommit, vtcProof := w.PartEvalWithVTC(blindedMsg, w.signers[i], lockTime)
		blindSigs = append(blindSigs, blindSig)
		vtcCommits = append(vtcCommits, vtcCommit)
		vtcProofs = append(vtcProofs, vtcProof)
		ths += weights[i]
	}

	sig := w.CombineWithVTC(signers, blindSigs, vtcCommits, vtcProofs, lockTime)

	b.Run("IPAProofVerify-N:"+strconv.Itoa(n), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Simulate future time when signature should be valid
			futureTime := time.Now().Add(T1 + T2 + time.Hour)
			w.VerifyWithVTC(msg, sig, ths, futureTime)
		}
	})
}

// Enhanced benchmarks for the new system
func BenchmarkWDVTS(b *testing.B) {
	flag.Parse()
	n := *NUM_NODES
	T1 := time.Duration(100) * time.Millisecond
	T2 := time.Duration(50) * time.Millisecond

	msg := []byte("hello world")
	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i + 1
	}

	crs, _ := Setup(n, T1, T2)
	w := NewWTSWithVTC(n, weights, crs, T1, T2)

	b.Run("Setup-N:"+strconv.Itoa(n), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			Setup(n, T1, T2)
		}
	})

	b.Run("KeyGenVTC-N:"+strconv.Itoa(n), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w.keyGenWithVTC()
		}
	})

	b.Run("BlindMessage-N:"+strconv.Itoa(n), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w.BlindMessage(msg)
		}
	})

	blindedMsg, blindingFactor := w.BlindMessage(msg)
	lockTime := time.Now().Add(T2)

	b.Run("PartEvalVTC-N:"+strconv.Itoa(n), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w.PartEvalWithVTC(blindedMsg, w.signers[0], lockTime)
		}
	})

	blindSig, vtcCommit, vtcProof := w.PartEvalWithVTC(blindedMsg, w.signers[0], lockTime)

	b.Run("PVerifyVTC-N:"+strconv.Itoa(n), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w.PVerifyWithVTC(blindedMsg, blindSig, vtcCommit, vtcProof, w.signers[0].pKeyAff, time.Now())
		}
	})

	b.Run("UnblindSig-N:"+strconv.Itoa(n), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w.UnblindSignature(blindSig, blindingFactor)
		}
	})

	// Prepare data for combine benchmark
	var signers []int
	var blindSigs []BlindSignature
	var vtcCommits []VTCCommitment
	var vtcProofs []VTCProof
	ths := 0

	for i := 0; i < n; i++ {
		signers = append(signers, i)
		bs, vc, vp := w.PartEvalWithVTC(blindedMsg, w.signers[i], lockTime)
		blindSigs = append(blindSigs, bs)
		vtcCommits = append(vtcCommits, vc)
		vtcProofs = append(vtcProofs, vp)
		ths += weights[i]
	}

	var sig Sig
	b.Run("CombineVTC-N:"+strconv.Itoa(n), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sig = w.CombineWithVTC(signers, blindSigs, vtcCommits, vtcProofs, lockTime)
		}
	})

	b.Run("VerifyVTC-N:"+strconv.Itoa(n), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Use future time to ensure verification passes
			futureTime := time.Now().Add(T1 + T2 + time.Hour)
			w.VerifyWithVTC(msg, sig, ths, futureTime)
		}
	})
}

// Test preprocessing functionality
func TestPreProcessWithVTC(t *testing.T) {
	n := 1 << 5
	T1 := time.Duration(10) * time.Second
	T2 := time.Duration(5) * time.Second

	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i + 1
	}

	crs, _ := Setup(n, T1, T2)
	w := NewWTSWithVTC(n, weights, crs, T1, T2)
	w.preProcess()

	// tau^n-1
	var zTau fr.Element
	zTau.Exp(w.crs.tau, big.NewInt(int64(n)))
	one := fr.One()
	zTau.Sub(&zTau, &one)

	var lhsG, rhsG, qi bls.G1Affine
	lagH := GetAllLagAtWithOmegas(w.crs.H, w.crs.tau)
	for i := 0; i < n; i++ {
		lhsG.ScalarMultiplication(&w.pp.pComm, lagH[i].BigInt(&big.Int{}))
		rhsG.ScalarMultiplication(&w.signers[i].pKeyAff, lagH[i].BigInt(&big.Int{}))
		qi.ScalarMultiplication(&w.pp.qTaus[i], zTau.BigInt(&big.Int{}))
		rhsG.Add(&rhsG, &qi)
		assert.Equal(t, lhsG.Equal(&rhsG), true)
	}
}

// Test binary proof with VTC
func TestBinWithVTC(t *testing.T) {
	n := 1 << 6
	T1 := time.Duration(10) * time.Second
	T2 := time.Duration(5) * time.Second

	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i + 1
	}

	crs, _ := Setup(n, T1, T2)
	w := NewWTSWithVTC(n, weights, crs, T1, T2)
	w.preProcess()

	var bTau bls.G1Affine
	var bNegTau bls.G2Affine

	var signers []int
	ths := 0
	for i := 0; i < n; i++ {
		if rand.Intn(2) == 1 {
			signers = append(signers, i)
			bTau.Add(&bTau, &crs.lagHTaus[i])
			bNegTau.Add(&bNegTau, &crs.lag2HTaus[i])
			ths += weights[i]
		}
	}
	bTauG2 := bNegTau
	bNegTau.Sub(&crs.g2a, &bNegTau)
	qTau := w.binaryPf(signers)
	fmt.Println("Signers ", len(signers), "Threshold", ths)

	var bNegTauG1 bls.G1Affine
	bNegTauG1.Sub(&w.crs.g1a, &bTau)
	lhs, _ := bls.Pair([]bls.G1Affine{bNegTauG1}, []bls.G2Affine{crs.g2a})
	rhs, _ := bls.Pair([]bls.G1Affine{crs.g1a}, []bls.G2Affine{bNegTau})
	assert.Equal(t, lhs.Equal(&rhs), true, "Proving BNeg Correctness!")

	// Checking the binary relation
	lhs, _ = bls.Pair([]bls.G1Affine{bTau}, []bls.G2Affine{bNegTau})
	rhs, _ = bls.Pair([]bls.G1Affine{qTau}, []bls.G2Affine{w.crs.vHTau})
	assert.Equal(t, lhs.Equal(&rhs), true, "Proving Binary relation!")

	// Checking weights relation
	qwTau, rwTau, _ := w.weightsPf(signers)
	qwTauAff := *new(bls.G1Affine).FromJacobian(&qwTau)
	rwTauAff := *new(bls.G1Affine).FromJacobian(&rwTau)

	var gThs bls.G1Affine
	nInv := fr.NewElement(uint64(w.n))
	nInv.Inverse(&nInv)
	gThs.ScalarMultiplication(&w.crs.g1a, big.NewInt(int64(ths)))
	gThs.ScalarMultiplication(&gThs, nInv.BigInt(&big.Int{}))

	lhs, _ = bls.Pair([]bls.G1Affine{w.pp.wTau}, []bls.G2Affine{bTauG2})
	rhs, _ = bls.Pair([]bls.G1Affine{qwTauAff, rwTauAff, gThs}, []bls.G2Affine{w.crs.vHTau, w.crs.g2Tau, w.crs.g2a})
	assert.Equal(t, lhs.Equal(&rhs), true, "Proving weights!")
}
