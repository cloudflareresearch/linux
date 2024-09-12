package signing_tool

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func generateRsa2048Key() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, rsaKeySizeBits)
}

func generateAndLoadRsaPrivateKey(name string) (RsaKey, *rsa.PrivateKey, error) {
	key, err := generateRsa2048Key()
	if err != nil {
		return RsaKey{}, nil, err
	}

	k, err := ProcessKeyring().LoadRsaPrivateKey(name, key)

	return k, key, err
}

func kernelSetupRsa2048(tb testing.TB, name string) (RsaKey, *rsa.PrivateKey, []byte, []byte) {
	k, kk, err := generateAndLoadRsaPrivateKey(name)
	require.NoError(tb, err)
	return k, kk, testMessageHash256(), k.MakeSignatureBuffer()
}

func TestRsa(t *testing.T) {
	k, kk, err := generateAndLoadRsaPrivateKey("rsa-2048-testkey")
	require.NoError(t, err)

	msgDigest := testMessageHash256()
	kernelSig := k.MakeSignatureBuffer()

	kernelSig, err = k.SignRsaPrehashed(msgDigest, kernelSig)
	require.NoError(t, err)

	t.Logf("%x", kernelSig)
	goSig, err := kk.Sign(rand.Reader, msgDigest, crypto.SHA256)
	require.NoError(t, err)

	require.NoError(t, k.VerifyRsaPrehashed(msgDigest, kernelSig))
	require.NoError(t, k.VerifyRsaPrehashed(msgDigest, goSig))
	require.NoError(t, rsa.VerifyPKCS1v15(&kk.PublicKey, crypto.SHA256, msgDigest, kernelSig))
	require.NoError(t, rsa.VerifyPKCS1v15(&kk.PublicKey, crypto.SHA256, msgDigest, goSig))
}

func BenchmarkRSAKernelSign(b *testing.B) {
	keyInKernel, _, digest, signature := kernelSetupRsa2048(b, "benchkey")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := keyInKernel.SignRsaPrehashed(digest[:], signature[:])
		if err != nil {
			b.Fatalf("failed to sign the digest: %v", err)
		}
	}
}

func BenchmarkRSAKernelVerify(b *testing.B) {
	keyInKernel, _, digest, signature := kernelSetupRsa2048(b, "benchkey")

	signature, err := keyInKernel.SignRsaPrehashed(digest[:], signature[:])
	if err != nil {
		b.Fatalf("failed to sign the digest: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := keyInKernel.VerifyRsaPrehashed(digest[:], signature[:])
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
