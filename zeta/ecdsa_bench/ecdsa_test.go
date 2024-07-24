package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func kernelSetup(b *testing.B) (KeySerial, []byte, []byte) {
	var (
		msg       = []byte("hello world")
		digest    = sha256.Sum256(msg)
		signature [64]byte
	)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate private key: %v", err)
	}

	keyInKernel := loadKeyToKernel(priv)

	return keyInKernel, digest[:], signature[:]
}

func BenchmarkECDSAKernelSign(b *testing.B) {
	keyInKernel, digest, signature := kernelSetup(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := keyInKernel.Sign(sha256pkcs1, digest[:], signature[:])
		if err != nil {
			b.Fatalf("failed to sign the digest: %v", err)
		}
	}
}

func BenchmarkECDSAKernelVerify(b *testing.B) {
	keyInKernel, digest, signature := kernelSetup(b)

	err := keyInKernel.Sign(sha256pkcs1, digest[:], signature[:])
	if err != nil {
		b.Fatalf("failed to sign the digest: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := keyInKernel.Verify(sha256pkcs1, digest[:], signature[:])
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
