package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"log"
	"testing"
)

func BenchmarkRSAKernel(b *testing.B) {
	const N = 2048

	var (
		msg       = []byte("hello world")
		digest    = sha256.Sum256(msg)
		signature [N / 8]byte
	)

	priv, err := rsa.GenerateKey(rand.Reader, N)
	if err != nil {
		log.Fatalf("failed to generate private key: %v", err)
	}

	keyInKernel := loadKeyToKernel(priv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := keyInKernel.Sign(sha256pkcs1, digest[:], signature[:])
		if err != nil {
			log.Fatalf("failed to sign the digest: %v", err)
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
		log.Fatalf("failed to generate private key: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := priv.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			log.Fatalf("failed to sign the digest: %v", err)
		}
	}
}
