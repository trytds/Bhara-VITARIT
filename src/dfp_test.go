package wts

import (
	"flag"
	"fmt"
	"math/big"
	"strconv"
	"testing"
	"time"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

var (
	NUM_PARTIES = flag.Int("parties", 10, "Number of parties")
	NUM_SECRETS = flag.Int("secrets", 5, "Number of secrets per party")
	THRESHOLD   = flag.Int("threshold", 3, "Threshold value")
)

func TestDFPBasic(t *testing.T) {
	m := 5  // 5 parties
	k := 3  // 3 secrets per party
	th := 2 // threshold = 2
	T1 := time.Duration(100) * time.Millisecond
	T2 := time.Duration(50) * time.Millisecond

	dfp := NewDFP(m, k, th, T1, T2)

	totalTime, err := dfp.ExecuteProtocol()
	if err != nil {
		t.Fatalf("Protocol execution failed: %v", err)
	}

	fmt.Printf("Basic DFP test completed in: %v\n", totalTime)
}

func TestDFPScalability(t *testing.T) {
	T1 := time.Duration(100) * time.Millisecond
	T2 := time.Duration(50) * time.Millisecond

	testCases := []struct {
		m, k, t int
		name    string
	}{
		{5, 3, 2, "Small"},
		{10, 5, 3, "Medium"},
		{20, 10, 7, "Large"},
		{84, 60, 12, "XLarge"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dfp := NewDFP(tc.m, tc.k, tc.t, T1, T2)

			totalTime, err := dfp.ExecuteProtocol()
			if err != nil {
				t.Fatalf("Protocol execution failed: %v", err)
			}

			fmt.Printf("%s DFP (m=%d, k=%d, t=%d): %v\n",
				tc.name, tc.m, tc.k, tc.t, totalTime)
		})
	}
}

func BenchmarkDFPSteps(b *testing.B) {
	flag.Parse()
	m := *NUM_PARTIES
	k := *NUM_SECRETS
	th := *THRESHOLD
	T1 := time.Duration(100) * time.Millisecond
	T2 := time.Duration(50) * time.Millisecond

	dfp := NewDFP(m, k, th, T1, T2)

	b.Run("Step1_CreateShares-"+strconv.Itoa(m), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dfp.Step1_CreateShares()
		}
	})

	b.Run("Step2_VTCCommitments-"+strconv.Itoa(m), func(b *testing.B) {
		dfp.Step1_CreateShares() // Setup
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dfp.Step2_GenerateVTCCommitments()
		}
	})

	b.Run("Step3_VerifyShares-"+strconv.Itoa(m), func(b *testing.B) {
		dfp.Step1_CreateShares()
		dfp.Step2_GenerateVTCCommitments()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dfp.Step3_VerifyShares()
		}
	})

	b.Run("Step4_RevealShares-"+strconv.Itoa(m), func(b *testing.B) {
		dfp.Step1_CreateShares()
		dfp.Step2_GenerateVTCCommitments()
		dfp.Step3_VerifyShares()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dfp.Step4_RevealShares()
		}
	})
}

func BenchmarkDFPComplete(b *testing.B) {
	flag.Parse()
	m := *NUM_PARTIES
	k := *NUM_SECRETS
	th := *THRESHOLD
	T1 := time.Duration(100) * time.Millisecond
	T2 := time.Duration(50) * time.Millisecond

	b.Run("Complete_DFP-"+strconv.Itoa(m), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dfp := NewDFP(m, k, th, T1, T2)
			dfp.ExecuteProtocol()
		}
	})
}

func BenchmarkDFPBySize(b *testing.B) {
	T1 := time.Duration(100) * time.Millisecond
	T2 := time.Duration(50) * time.Millisecond

	sizes := []struct{ m, k, t int }{
		{5, 3, 2},
		{10, 5, 3},
		{20, 10, 7},
		{30, 15, 10},
		{84, 60, 12},
	}

	for _, size := range sizes {
		name := fmt.Sprintf("DFP-m%d-k%d-t%d", size.m, size.k, size.t)
		b.Run(name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				dfp := NewDFP(size.m, size.k, size.t, T1, T2)
				dfp.ExecuteProtocol()
			}
		})
	}
}

func BenchmarkVTCOperations(b *testing.B) {
	flag.Parse()
	m := *NUM_PARTIES
	k := *NUM_SECRETS
	th := *THRESHOLD
	T1 := time.Duration(100) * time.Millisecond
	T2 := time.Duration(50) * time.Millisecond

	dfp := NewDFP(m, k, th, T1, T2)

	b.Run("VTC_Commit-"+strconv.Itoa(m), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			lockTime := time.Now().Add(T1)
			var share fr.Element
			share.SetRandom()

			_ = VTCCommitment_DFP{
				commitment: *new(bls.G1Affine).ScalarMultiplication(&dfp.params.h, share.BigInt(&big.Int{})),
				lockTime:   lockTime,
			}
		}
	})

	b.Run("VTC_Verify-"+strconv.Itoa(m), func(b *testing.B) {
		// Setup commitment
		var share fr.Element
		share.SetRandom()
		commitment := VTCCommitment_DFP{
			commitment: *new(bls.G1Affine).ScalarMultiplication(&dfp.params.h, share.BigInt(&big.Int{})),
			lockTime:   time.Now().Add(T1),
		}
		proof := VTCProof_DFP{
			pi: *new(bls.G1Affine).ScalarMultiplication(&dfp.params.h, share.BigInt(&big.Int{})),
			t:  time.Now().Add(T1),
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dfp.verifyVTCCommitment(commitment, proof)
		}
	})
}

func BenchmarkLagrangeOperations(b *testing.B) {
	flag.Parse()
	m := *NUM_PARTIES
	k := *NUM_SECRETS
	th := *THRESHOLD
	T1 := time.Duration(100) * time.Millisecond
	T2 := time.Duration(50) * time.Millisecond

	dfp := NewDFP(m, k, th, T1, T2)

	b.Run("Polynomial_Creation-"+strconv.Itoa(m), func(b *testing.B) {
		var secret fr.Element
		secret.SetRandom()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dfp.createSharingPolynomial(secret, 0)
		}
	})

	b.Run("Polynomial_Evaluation-"+strconv.Itoa(m), func(b *testing.B) {
		var secret fr.Element
		secret.SetRandom()
		poly := dfp.createSharingPolynomial(secret, 0)
		point := fr.NewElement(uint64(1))

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dfp.evaluatePolynomial(poly, point)
		}
	})

	b.Run("Secret_Reconstruction-"+strconv.Itoa(m), func(b *testing.B) {
		// Setup shares
		dfp.Step1_CreateShares()
		dfp.Step2_GenerateVTCCommitments()
		dfp.Step3_VerifyShares()
		dfp.Step4_RevealShares()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if dfp.hasEnoughShares(0) {
				dfp.reconstructSecret(0)
			}
		}
	})
}
