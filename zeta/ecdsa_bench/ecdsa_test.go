package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"
)

func kernelSetup(priv *ecdsa.PrivateKey) (KeySerial, []byte, []byte) {
	var (
		msg       = []byte("hello world")
		digest    = sha256.Sum256(msg)
		signature [72]byte
	)

	keyInKernel := loadKeyToKernel(priv)

	return keyInKernel, digest[:], signature[:]
}

func TestSignInKernelVerifyInGo(t *testing.T) {
	var (
		msg       = []byte("hello world")
		digest    = sha256.Sum256(msg)
		signature [72]byte
	)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	keyInKernel := loadKeyToKernel(priv)

	n, err := keyInKernel.Sign(signInfo, digest[:], signature[:])
	if err != nil {
		t.Fatalf("failed to sign the digest: %v", err)
	}

	fmt.Printf("got signature %x (len: %v, n: %v)\n", signature, len(signature), n)
	fmt.Printf("got signature %x\n", signature[:n])

	ok := ecdsa.VerifyASN1(&priv.PublicKey, digest[:], signature[:n])
	if !ok {
		t.Log("failed to verify the signature using pre-hashed, trying with sha256...")
		digestDigest := sha256.Sum256(digest[:])
		ok := ecdsa.VerifyASN1(&priv.PublicKey, digestDigest[:], signature[:])
		if !ok {
			t.Fatalf("failed to verify the signature with sha256 as well")
		}
	}
}

func TestSignAndVerifyInKernel(t *testing.T) {
	var (
		msg       = []byte("hello world")
		digest    = sha256.Sum256(msg)
		signature [72]byte
	)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	keyInKernel := loadKeyToKernel(priv)

	n, err := keyInKernel.Sign(signInfo, digest[:], signature[:])
	if err != nil {
		t.Fatalf("failed to sign the digest: %v", err)
	}

	fmt.Printf("got signature %x (len: %v, n: %v)\n", signature, len(signature), n)
	fmt.Printf("got signature %x\n", signature[:n])

	err = keyInKernel.Verify(signInfo, digest[:], signature[:n])
	if err != nil {
		t.Logf("failed to verify the signature using pre-hashed: %v, trying with sha256...", err)
		digestDigest := sha256.Sum256(digest[:])
		err = keyInKernel.Verify(signInfo, digestDigest[:], signature[:n])
		if err != nil {
			t.Fatalf("failed to verify the signature with sha256 as well: %v", err)
		}
	}
}

func BenchmarkECDSAKernelSign(b *testing.B) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate private key: %v", err)
	}

	keyInKernel, digest, signature := kernelSetup(priv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := keyInKernel.Sign(signInfo, digest[:], signature[:])
		if err != nil {
			b.Fatalf("failed to sign the digest: %v", err)
		}
	}
}

func BenchmarkECDSAKernelVerify(b *testing.B) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate private key: %v", err)
	}

	keyInKernel, digest, signature := kernelSetup(priv)

	n, err := keyInKernel.Sign(signInfo, digest[:], signature[:])
	if err != nil {
		b.Fatalf("failed to sign the digest: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := keyInKernel.Verify(signInfo, digest[:], signature[:n])
		if err != nil {
			b.Fatalf("failed to sign the digest: %v", err)
		}
	}
}

func BenchmarkECDSAGo(b *testing.B) {
	var (
		msg    = []byte("hello world")
		digest = sha256.Sum256(msg)
	)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate private key: %v", err)
	}

	signature, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		b.Fatalf("failed to sign the digest: %v", err)
	}

	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := priv.Sign(rand.Reader, digest[:], crypto.SHA256)
			if err != nil {
				b.Fatalf("failed to sign the digest: %v", err)
			}
		}
	})

	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ok := ecdsa.VerifyASN1(&priv.PublicKey, digest[:], signature[:])
			if !ok {
				b.Fatalf("failed to sign the digest: %v", err)
			}
		}
	})
}
