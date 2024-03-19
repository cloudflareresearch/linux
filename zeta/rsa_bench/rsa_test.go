package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func kernelSetup(b *testing.B) (KeySerial, []byte, []byte) {
	const N = 2048

	var (
		msg       = []byte("hello world")
		digest    = sha256.Sum256(msg)
		signature [N / 8]byte
	)

	priv, err := rsa.GenerateKey(rand.Reader, N)
	if err != nil {
		b.Fatalf("failed to generate private key: %v", err)
	}

	keyInKernel := loadKeyToKernel(priv)

	return keyInKernel, digest[:], signature[:]
}

func BenchmarkRSAKernelSign(b *testing.B) {
	keyInKernel, digest, signature := kernelSetup(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := keyInKernel.Sign(sha256pkcs1, digest[:], signature[:])
		if err != nil {
			b.Fatalf("failed to sign the digest: %v", err)
		}
	}
}

func BenchmarkRSAKernelVerify(b *testing.B) {
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

func BenchmarkRSAGo(b *testing.B) {
	const N = 2048

	var (
		msg    = []byte("hello world")
		digest = sha256.Sum256(msg)
	)

	priv, err := rsa.GenerateKey(rand.Reader, N)
	if err != nil {
		b.Fatalf("failed to generate private key: %v", err)
	}

	signature, err := priv.Sign(rand.Reader, digest[:], crypto.SHA256)
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
			err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, digest[:], signature[:])
			if err != nil {
				b.Fatalf("failed to sign the digest: %v", err)
			}
		}
	})
}
