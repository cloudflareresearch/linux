package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"runtime"
	"testing"
)

var signInfo384 = []byte("enc=x962 hash=sha384\x00")

func kernelSetup256(priv *ecdsa.PrivateKey) (KeySerial, []byte, []byte) {
	var (
		msg       = []byte("hello world")
		digest    = sha256.Sum256(msg)
		signature [72]byte
	)

	keyInKernel := loadKeyToKernel(priv)

	return keyInKernel, digest[:], signature[:]
}

func kernelSetup384(priv *ecdsa.PrivateKey) (KeySerial, []byte, []byte) {
	var (
		msg       = []byte("hello world")
		digest    = sha256.Sum256(msg)
		signature [256]byte
	)

	keyInKernel := loadKeyToKernel(priv)

	return keyInKernel, digest[:], signature[:]
}

func TestSign384InKernelVerifyInGo(t *testing.T) {
	runtime.LockOSThread()

	var (
		msg       = []byte("hello world")
		digest    = sha512.Sum384(msg)
		signature [256]byte
	)

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	keyInKernel := loadKeyToKernel(priv)

	n, err := keyInKernel.Sign(signInfo384, digest[:], signature[:])
	if err != nil {
		t.Fatalf("failed to sign the digest: %v", err)
	}

	ok := ecdsa.VerifyASN1(&priv.PublicKey, digest[:], signature[:n])
	if !ok {
		t.Fatalf("failed to verify the signature")
	}
}

func TestSignInKernelVerifyInGo(t *testing.T) {
	runtime.LockOSThread()

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

	ok := ecdsa.VerifyASN1(&priv.PublicKey, digest[:], signature[:n])
	if !ok {
		t.Fatalf("failed to verify the signature")
	}
}

func TestSignAndVerifyInKernel(t *testing.T) {
	runtime.LockOSThread()

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

	err = keyInKernel.Verify(signInfo, digest[:], signature[:n])
	if err != nil {
		t.Fatalf("failed to verify the signature: %v", err)
	}
}

func BenchmarkECDSAP384KernelSign(b *testing.B) {
	runtime.LockOSThread()

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate private key: %v", err)
	}

	keyInKernel, digest, signature := kernelSetup384(priv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := keyInKernel.Sign(signInfo384, digest[:], signature[:])
		if err != nil {
			b.Fatalf("failed to sign the digest: %v", err)
		}
	}
}

func BenchmarkECDSAP384KernelVerify(b *testing.B) {
	runtime.LockOSThread()

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate private key: %v", err)
	}

	keyInKernel, digest, signature := kernelSetup384(priv)

	n, err := keyInKernel.Sign(signInfo384, digest[:], signature[:])
	if err != nil {
		b.Fatalf("failed to sign the digest: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := keyInKernel.Verify(signInfo384, digest[:], signature[:n])
		if err != nil {
			b.Fatalf("failed to verify the signature: %v", err)
		}
	}
}

func BenchmarkECDSAP256KernelSign(b *testing.B) {
	runtime.LockOSThread()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate private key: %v", err)
	}

	keyInKernel, digest, signature := kernelSetup256(priv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := keyInKernel.Sign(signInfo, digest[:], signature[:])
		if err != nil {
			b.Fatalf("failed to sign the digest: %v", err)
		}
	}
}

func BenchmarkECDSAP256KernelVerify(b *testing.B) {
	runtime.LockOSThread()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate private key: %v", err)
	}

	keyInKernel, digest, signature := kernelSetup256(priv)

	n, err := keyInKernel.Sign(signInfo, digest[:], signature[:])
	if err != nil {
		b.Fatalf("failed to sign the digest: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := keyInKernel.Verify(signInfo, digest[:], signature[:n])
		if err != nil {
			b.Fatalf("failed to verify the signature: %v", err)
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
				b.Fatalf("failed to verify the signature: %v", err)
			}
		}
	})
}
