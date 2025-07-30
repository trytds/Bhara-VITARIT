package wts

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"time"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
)

// VTC related structures for the freeze protocol
type VTCCommitment_DFP struct {
	commitment bls.G1Affine
	proof      bls.G1Affine
	lockTime   time.Time
}

type VTCProof_DFP struct {
	pi bls.G1Affine
	t  time.Time
}

// Secret sharing structures
type SecretShare struct {
	index int
	value fr.Element
}

type LockedShare struct {
	share      SecretShare
	commitment VTCCommitment_DFP
	proof      VTCProof_DFP
}

// Lagrange polynomial structure
type LagrangePolynomial struct {
	coefficients []fr.Element
	degree       int
}

// Party structure for DFP
type Party_DFP struct {
	id       int
	tsk      []fr.Element // Secret keys to be shared
	shares   []SecretShare
	vtcProfs []VTCProof_DFP
	pubKey   bls.G1Affine
}

// DFP protocol parameters
type DFPParams struct {
	g1     bls.G1Affine
	g2     bls.G2Affine
	h      bls.G1Affine // VTC generator
	domain *fft.Domain
	T1     time.Duration // Lock time
	T2     time.Duration // Reveal time
}

// DFP protocol state
type DFP struct {
	params        DFPParams
	parties       []Party_DFP
	m             int            // number of parties
	k             int            // number of secrets per party
	t             int            // threshold
	tpk           []bls.G1Affine // Public keys
	lockedShares  [][]LockedShare
	commitments   []VTCCommitment_DFP
	reconstructed [][]fr.Element
}

// Initialize DFP protocol
func NewDFP(m, k, t int, T1, T2 time.Duration) *DFP {
	// Generate public parameters
	g1Jac, g2Jac, _, _ := bls.Generators()
	var g1 bls.G1Affine
	var g2 bls.G2Affine
	g1.FromJacobian(&g1Jac)
	g2.FromJacobian(&g2Jac)

	var hSeed fr.Element
	hSeed.SetRandom()
	h := *new(bls.G1Affine).ScalarMultiplication(&g1, hSeed.BigInt(&big.Int{}))

	domain := fft.NewDomain(uint64(m))

	params := DFPParams{
		g1:     g1,
		g2:     g2,
		h:      h,
		domain: domain,
		T1:     T1,
		T2:     T2,
	}

	parties := make([]Party_DFP, m)
	for i := 0; i < m; i++ {
		parties[i] = Party_DFP{
			id:     i,
			tsk:    make([]fr.Element, k),
			shares: make([]SecretShare, 0),
		}

		// Generate k secret keys for each party
		for j := 0; j < k; j++ {
			parties[i].tsk[j].SetRandom()
		}

		// Generate public key
		var sk fr.Element
		sk.SetRandom()
		parties[i].pubKey = *new(bls.G1Affine).ScalarMultiplication(&g1, sk.BigInt(&big.Int{}))
	}

	return &DFP{
		params:        params,
		parties:       parties,
		m:             m,
		k:             k,
		t:             t,
		tpk:           make([]bls.G1Affine, k),
		lockedShares:  make([][]LockedShare, m),
		commitments:   make([]VTCCommitment_DFP, 0),
		reconstructed: make([][]fr.Element, m),
	}
}

// Step 1: U0 picks secret tsk0 and creates shares
func (dfp *DFP) Step1_CreateShares() time.Duration {
	start := time.Now()

	party0 := &dfp.parties[0]

	// For each secret key in tsk0
	for keyIdx := 0; keyIdx < dfp.k; keyIdx++ {
		secret := party0.tsk[keyIdx]

		// Create degree-t polynomial f(x) such that f(pi) = tsk0[i] and f(αi) = wi
		poly := dfp.createSharingPolynomial(secret, keyIdx)

		// Generate shares for all parties
		for i := 1; i <= dfp.m; i++ {
			point := fr.NewElement(uint64(i))
			share := dfp.evaluatePolynomial(poly, point)

			dfp.parties[i-1].shares = append(dfp.parties[i-1].shares, SecretShare{
				index: keyIdx,
				value: share,
			})
		}

		// Compute tpki = g^(tsk0[i])
		dfp.tpk[keyIdx] = *new(bls.G1Affine).ScalarMultiplication(&dfp.params.g1, secret.BigInt(&big.Int{}))
	}

	return time.Since(start)
}

// Step 2: U0 generates VTC commitments
func (dfp *DFP) Step2_GenerateVTCCommitments() time.Duration {
	start := time.Now()

	lockTime := time.Now().Add(dfp.params.T1)

	// For each party (except U0)
	for i := 1; i < dfp.m; i++ {
		party := &dfp.parties[i]

		// Create VTC commitment for each share
		lockedShares := make([]LockedShare, len(party.shares))

		for j, share := range party.shares {
			// Generate VTC commitment
			var r fr.Element
			r.SetRandom()

			commitment := VTCCommitment_DFP{
				commitment: *new(bls.G1Affine).ScalarMultiplication(&dfp.params.h, share.value.BigInt(&big.Int{})),
				proof:      *new(bls.G1Affine).ScalarMultiplication(&dfp.params.g1, r.BigInt(&big.Int{})),
				lockTime:   lockTime,
			}

			proof := VTCProof_DFP{
				pi: *new(bls.G1Affine).ScalarMultiplication(&dfp.params.h, r.BigInt(&big.Int{})),
				t:  lockTime,
			}

			lockedShares[j] = LockedShare{
				share:      share,
				commitment: commitment,
				proof:      proof,
			}
		}

		dfp.lockedShares[i] = lockedShares
	}

	return time.Since(start)
}

// Step 3: Verify shares and commitments
func (dfp *DFP) Step3_VerifyShares() time.Duration {
	start := time.Now()

	// Verify consistency of shares
	for i := 0; i < dfp.m; i++ {
		//party := &dfp.parties[i]

		// Sample random code y = (y1, ..., ym) from C⊥
		y := dfp.sampleRandomCode()

		// Check if Σ tpkj^yj = 1
		var product bls.G1Jac
		product.FromAffine(&dfp.params.g1) // Initialize to identity

		for j := 0; j < dfp.k; j++ {
			temp := *new(bls.G1Affine).ScalarMultiplication(&dfp.tpk[j], y[j].BigInt(&big.Int{}))
			product.AddMixed(&temp)
		}

		// Check if result is identity (simplified check)
		result := new(bls.G1Affine).FromJacobian(&product)
		_ = result // In practice, would verify this equals identity
	}

	// Verify VTC commitments
	for i := 1; i < dfp.m; i++ {
		for _, lockedShare := range dfp.lockedShares[i] {
			// VTC.Verify(pp, tpki, Ci, πi)
			dfp.verifyVTCCommitment(lockedShare.commitment, lockedShare.proof)
		}
	}

	return time.Since(start)
}

// Step 4: Reveal shares after T2
func (dfp *DFP) Step4_RevealShares() time.Duration {
	start := time.Now()

	// Wait for T2 to pass (simulated)
	revealTime := time.Now().Add(dfp.params.T2)

	// For each party, solve VTC and reveal shares
	for i := 1; i < dfp.m; i++ {
		shares := make([]fr.Element, len(dfp.lockedShares[i]))

		for j, lockedShare := range dfp.lockedShares[i] {
			// VTC.Solve(pp, Ci) to obtain share wi
			share := dfp.solveVTC(lockedShare.commitment, revealTime)
			shares[j] = share

			// Generate transaction tx_f_{i,j} and signature
			tx := dfp.generateTransaction(i, j, share)
			signature := dfp.signTransaction(tx, dfp.parties[i])
			_ = signature // Post (tx, σ) on blockchain (simulated)
		}

		dfp.reconstructed[i] = shares
	}

	// Reconstruct secrets using Lagrange interpolation
	for keyIdx := 0; keyIdx < dfp.k; keyIdx++ {
		if dfp.hasEnoughShares(keyIdx) {
			secret := dfp.reconstructSecret(keyIdx)
			_ = secret // Reconstructed tsk0[keyIdx]
		}
	}

	return time.Since(start)
}

// Helper functions

func (dfp *DFP) createSharingPolynomial(secret fr.Element, keyIdx int) LagrangePolynomial {
	// Create degree-t polynomial with f(0) = secret
	coeffs := make([]fr.Element, dfp.t+1)
	coeffs[0] = secret

	for i := 1; i <= dfp.t; i++ {
		coeffs[i].SetRandom()
	}

	return LagrangePolynomial{
		coefficients: coeffs,
		degree:       dfp.t,
	}
}

func (dfp *DFP) evaluatePolynomial(poly LagrangePolynomial, x fr.Element) fr.Element {
	var result fr.Element
	var xPower fr.Element
	xPower.SetOne()

	for i := 0; i <= poly.degree; i++ {
		var term fr.Element
		term.Mul(&poly.coefficients[i], &xPower)
		result.Add(&result, &term)
		xPower.Mul(&xPower, &x)
	}

	return result
}

func (dfp *DFP) sampleRandomCode() []fr.Element {
	// Sample random codeword from C⊥
	code := make([]fr.Element, dfp.k)
	for i := 0; i < dfp.k; i++ {
		code[i].SetRandom()
	}
	return code
}

func (dfp *DFP) verifyVTCCommitment(commitment VTCCommitment_DFP, proof VTCProof_DFP) bool {
	// Simplified VTC verification
	return !commitment.commitment.IsInfinity() && !proof.pi.IsInfinity()
}

func (dfp *DFP) solveVTC(commitment VTCCommitment_DFP, revealTime time.Time) fr.Element {
	// Simplified VTC solving - in practice would use VDF
	var solution fr.Element
	solution.SetRandom()
	return solution
}

func (dfp *DFP) generateTransaction(partyId, shareIdx int, share fr.Element) []byte {
	// Generate transaction data
	data := make([]byte, 32)
	shareBytes := share.Bytes()
	copy(data, shareBytes[:])
	return data
}

func (dfp *DFP) signTransaction(tx []byte, party Party_DFP) []byte {
	// Simple signature generation
	hash := sha256.Sum256(tx)
	return hash[:]
}

func (dfp *DFP) hasEnoughShares(keyIdx int) bool {
	count := 0
	for i := 0; i < dfp.m; i++ {
		if len(dfp.reconstructed[i]) > keyIdx {
			count++
		}
	}
	return count >= dfp.t+1
}

func (dfp *DFP) reconstructSecret(keyIdx int) fr.Element {
	// Collect enough shares
	shares := make([]SecretShare, 0)
	indices := make([]fr.Element, 0)

	for i := 0; i < dfp.m && len(shares) <= dfp.t; i++ {
		if len(dfp.reconstructed[i]) > keyIdx {
			shares = append(shares, SecretShare{
				index: i + 1,
				value: dfp.reconstructed[i][keyIdx],
			})
			indices = append(indices, fr.NewElement(uint64(i+1)))
		}
	}

	// Lagrange interpolation at x=0
	var secret fr.Element
	for i := 0; i < len(shares); i++ {
		// Compute Lagrange coefficient
		var coeff fr.Element
		coeff.SetOne()

		for j := 0; j < len(shares); j++ {
			if i != j {
				var num, den fr.Element
				num.Neg(&indices[j])
				den.Sub(&indices[i], &indices[j])
				den.Inverse(&den)
				num.Mul(&num, &den)
				coeff.Mul(&coeff, &num)
			}
		}

		var term fr.Element
		term.Mul(&shares[i].value, &coeff)
		secret.Add(&secret, &term)
	}

	return secret
}

// Complete DFP protocol execution
func (dfp *DFP) ExecuteProtocol() (time.Duration, error) {
	start := time.Now()

	fmt.Println("=== DFP Protocol Execution ===")

	// Step 1: Create shares
	step1Time := dfp.Step1_CreateShares()
	fmt.Printf("Step 1 (Create Shares): %v\n", step1Time)

	// Step 2: Generate VTC commitments
	step2Time := dfp.Step2_GenerateVTCCommitments()
	fmt.Printf("Step 2 (VTC Commitments): %v\n", step2Time)

	// Step 3: Verify shares
	step3Time := dfp.Step3_VerifyShares()
	fmt.Printf("Step 3 (Verify Shares): %v\n", step3Time)

	// Step 4: Reveal shares
	step4Time := dfp.Step4_RevealShares()
	fmt.Printf("Step 4 (Reveal Shares): %v\n", step4Time)

	totalTime := time.Since(start)
	fmt.Printf("Total Protocol Time: %v\n", totalTime)

	return totalTime, nil
}
