package wts

import (
	"crypto/sha256"
	"math/big"
	"time"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type Secret = fr.Element
type Public = bls.G1Affine

type AdaptorSignature struct {
	R bls.G1Affine
	S fr.Element
	E []byte
}

type Signature struct {
	R bls.G1Affine
	S fr.Element
}

// 1. 生成密钥对
func KeyGen() (Secret, Public) {
	var sk fr.Element
	sk.SetRandom()
	g1Jac, _, _, _ := bls.Generators()
	var g1Aff bls.G1Affine
	g1Aff.FromJacobian(&g1Jac)
	pk := *new(bls.G1Affine).ScalarMultiplication(&g1Aff, sk.BigInt(new(big.Int)))
	return sk, pk
}

// 2. 创建适配器签名
func AdaptorSign(sk Secret, msg []byte, Y Public) (AdaptorSignature, time.Duration) {
	start := time.Now()
	g1Jac, _, _, _ := bls.Generators()
	var g1Aff bls.G1Affine
	g1Aff.FromJacobian(&g1Jac)

	// 生成随机k
	var k fr.Element
	k.SetRandom()
	R := *new(bls.G1Affine).ScalarMultiplication(&g1Aff, k.BigInt(new(big.Int)))

	// R' = R + Y
	Rp := R
	Rp.Add(&Rp, &Y)

	// e = H(m || Rp)
	h := sha256.New()
	h.Write(msg)
	rpBytes := Rp.Bytes()
	h.Write(rpBytes[:])
	eBytes := h.Sum(nil)

	var e fr.Element
	e.SetBytes(eBytes[:])

	// s = k + e*sk
	var esk fr.Element
	esk.Mul(&e, &sk)
	s := k
	s.Add(&s, &esk)

	return AdaptorSignature{R: R, S: s, E: eBytes}, time.Since(start)
}

// 3. 完成签名
func CompleteSignature(adaptorSig AdaptorSignature, x Secret, Y Public) (Signature, time.Duration) {
	start := time.Now()
	Rp := adaptorSig.R
	Rp.Add(&Rp, &Y)
	s := adaptorSig.S
	s.Add(&s, &x)
	return Signature{R: Rp, S: s}, time.Since(start)
}

// 4. 验证
func Verify(pk Public, msg []byte, sig Signature) bool {
	h := sha256.New()
	h.Write(msg)
	sigRBytes := sig.R.Bytes()
	h.Write(sigRBytes[:])
	eBytes := h.Sum(nil)

	var e fr.Element
	e.SetBytes(eBytes[:])

	g1Jac, _, _, _ := bls.Generators()
	var g1Aff bls.G1Affine
	g1Aff.FromJacobian(&g1Jac)

	left := new(bls.G1Affine).ScalarMultiplication(&g1Aff, sig.S.BigInt(new(big.Int)))
	pkPow := new(bls.G1Affine).ScalarMultiplication(&pk, e.BigInt(new(big.Int)))
	right := sig.R
	right.Add(&right, pkPow)
	return left.Equal(&right)
}

// 5. 提取适配器私钥
func ExtractSecret(sig Signature, adaptorSig AdaptorSignature) Secret {
	var x fr.Element
	x.Sub(&sig.S, &adaptorSig.S)
	return x
}
