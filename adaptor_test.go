package wts

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestAdaptorSignatureFlow(t *testing.T) {
	msg := []byte("Adaptor Signature example")

	// 生成主签名密钥对
	sk, pk := KeyGen()
	// 生成适配器密钥对
	x, Y := KeyGen()

	pkBytes := pk.Bytes()
	yBytes := Y.Bytes()
	t.Logf("主签名公钥: %x...", pkBytes[:8])
	t.Logf("适配器公钥: %x...", yBytes[:8])

	// 1. 生成适配器签名
	adaptorSig, tSign := AdaptorSign(sk, msg, Y)
	t.Logf("适配器签名生成时间: %v", tSign)

	// 2. 适配器私钥拥有者还原普通签名
	sig, tComp := CompleteSignature(adaptorSig, x, Y)
	t.Logf("普通签名还原时间: %v", tComp)

	// 3. 验证普通签名
	ok := Verify(pk, msg, sig)
	if !ok {
		t.Fatal("普通签名验证失败")
	}
	t.Log("普通签名验证通过")

	// 4. 提取适配器私钥
	x2 := ExtractSecret(sig, adaptorSig)
	x2Bytes := x2.Bytes()
	xBytes := x.Bytes()
	if !bytes.Equal(x2Bytes[:], xBytes[:]) {
		t.Fatal("提取出的适配器私钥不一致")
	}
	t.Log("适配器私钥提取正确")
}

func HashAdaptor(msg []byte, rp Public) []byte {
	h := sha256.New()
	h.Write(msg)
	rpBytes := rp.Bytes()
	h.Write(rpBytes[:])
	return h.Sum(nil)
}

func BenchmarkAdaptorSign(b *testing.B) {
	msg := []byte("benchmark adaptor sign")
	sk, _ := KeyGen()
	_, Y := KeyGen()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AdaptorSign(sk, msg, Y)
	}
}

func BenchmarkAdaptorVerifyHash(b *testing.B) {
	msg := []byte("benchmark adaptor verify")
	sk, _ := KeyGen()
	_, Y := KeyGen()
	adaptorSig, _ := AdaptorSign(sk, msg, Y)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rp := adaptorSig.R
		rp.Add(&rp, &Y)
		HashAdaptor(msg, rp)
	}
}

func BenchmarkWitnessExtract(b *testing.B) {
	msg := []byte("benchmark witness extract")
	sk, _ := KeyGen()
	x, Y := KeyGen()
	adaptorSig, _ := AdaptorSign(sk, msg, Y)
	completeSig, _ := CompleteSignature(adaptorSig, x, Y)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractSecret(completeSig, adaptorSig)
	}
}

func BenchmarkCompleteSignature(b *testing.B) {
	msg := []byte("benchmark complete signature")
	sk, _ := KeyGen()
	x, Y := KeyGen()
	adaptorSig, _ := AdaptorSign(sk, msg, Y)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CompleteSignature(adaptorSig, x, Y)
	}
}
