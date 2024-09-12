package signing_tool

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

const testMessage = "This is the message to be signed"

func testMessageHash256() []byte {
	sum := sha256.Sum256([]byte(testMessage))
	return sum[:]
}

func testMessageHash384() []byte {
	sum := sha512.Sum384([]byte(testMessage))
	return sum[:]
}

func generateEcdsaP256Key() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func generateEcdsaP384Key() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

func generateAndLoadEcdsaP256PrivateKey(name string) (EcdsaKey, *ecdsa.PrivateKey, error) {
	key, err := generateEcdsaP256Key()
	if err != nil {
		return EcdsaKey{}, nil, err
	}

	kernelKey, err := ProcessKeyring().LoadEcdsaPrivateKey(name, key)

	return kernelKey, key, err
}

func generateAndLoadEcdsaP384PrivateKey(name string) (EcdsaKey, *ecdsa.PrivateKey, error) {
	key, err := generateEcdsaP384Key()
	if err != nil {
		return EcdsaKey{}, nil, err
	}

	kernelKey, err := ProcessKeyring().LoadEcdsaPrivateKey(name, key)
	return kernelKey, key, err
}

func kernelSetupEcdsa256(tb testing.TB, name string) (EcdsaKey, *ecdsa.PrivateKey, []byte, []byte) {
	k, kk, err := generateAndLoadEcdsaP256PrivateKey(name)
	require.NoError(tb, err)
	return k, kk, testMessageHash256(), k.MakeSignatureBuffer()
}

func kernelSetupEcdsa384(tb testing.TB, name string) (EcdsaKey, *ecdsa.PrivateKey, []byte, []byte) {
	k, kk, err := generateAndLoadEcdsaP384PrivateKey(name)
	require.NoError(tb, err)
	return k, kk, testMessageHash384(), k.MakeSignatureBuffer()
}

func TestEcdsa256(t *testing.T) {
	k, kk, err := generateAndLoadEcdsaP256PrivateKey("ecdsa-p256-testkey")
	require.NoError(t, err)

	msgDigest := testMessageHash256()

	kernelSig := k.MakeSignatureBuffer()
	kernelSig, err = k.SignPrehashed(msgDigest, kernelSig)
	require.NoError(t, err)
	goSig, err := kk.Sign(rand.Reader, msgDigest, crypto.SHA256)
	require.NoError(t, err)

	err = k.VerifyPrehashed(msgDigest, kernelSig)
	require.NoError(t, err)
	err = k.VerifyPrehashed(msgDigest, goSig)
	require.NoError(t, err)

	require.True(t, ecdsa.VerifyASN1(&kk.PublicKey, msgDigest, kernelSig))
	require.True(t, ecdsa.VerifyASN1(&kk.PublicKey, msgDigest, goSig))
}

func TestEcdsa384(t *testing.T) {
	k, kk, err := generateAndLoadEcdsaP384PrivateKey("ecdsa-p384-testkey")
	require.NoError(t, err)

	msgDigest := testMessageHash384()

	kernelSig := k.MakeSignatureBuffer()
	kernelSig, err = k.SignPrehashed(msgDigest, kernelSig)
	require.NoError(t, err)
	goSig, err := kk.Sign(rand.Reader, msgDigest, crypto.SHA384)
	require.NoError(t, err)

	err = k.VerifyPrehashed(msgDigest, kernelSig)
	require.NoError(t, err)
	err = k.VerifyPrehashed(msgDigest, goSig)
	require.NoError(t, err)

	require.True(t, ecdsa.VerifyASN1(&kk.PublicKey, msgDigest, kernelSig))
	require.True(t, ecdsa.VerifyASN1(&kk.PublicKey, msgDigest, goSig))
}

func BenchmarkECDSAP384KernelSign(b *testing.B) {
	runtime.LockOSThread()

	keyInKernel, _, digest, signature := kernelSetupEcdsa384(b, "benchkey")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := keyInKernel.SignPrehashed(digest, signature)
		if err != nil {
			b.Fatalf("failed to sign the digest: %v", err)
		}
	}
}

func BenchmarkECDSAP384KernelVerify(b *testing.B) {
	runtime.LockOSThread()

	keyInKernel, _, digest, signature := kernelSetupEcdsa384(b, "benchkey")

	signature, err := keyInKernel.SignPrehashed(digest, signature)
	if err != nil {
		b.Fatalf("failed to sign the digest: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := keyInKernel.VerifyPrehashed(digest[:], signature[:])
		if err != nil {
			b.Fatalf("failed to verify the signature: %v", err)
		}
	}
}

func BenchmarkECDSAP256KernelSign(b *testing.B) {
	runtime.LockOSThread()

	keyInKernel, _, digest, signature := kernelSetupEcdsa256(b, "benchkey")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := keyInKernel.SignPrehashed(digest, signature)
		if err != nil {
			b.Fatalf("failed to sign the digest: %v", err)
		}
	}
}

func BenchmarkECDSAP256KernelVerify(b *testing.B) {
	runtime.LockOSThread()

	keyInKernel, _, digest, signature := kernelSetupEcdsa256(b, "benchkey")

	signature, err := keyInKernel.SignPrehashed(digest, signature)
	if err != nil {
		b.Fatalf("failed to sign the digest: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := keyInKernel.VerifyPrehashed(digest, signature)
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
