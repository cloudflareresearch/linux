package signing_tool // import "github.com/cryspen/signing_tool"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

type (
	KeySerial int32
	Keyring   int32
	KeyOps    = uintptr
)

// Turns a string that already are 0-terminated into a pointer to the first byte
// of the string, effectively making it a C String.
func toCString(str string) *byte {
	return &[]byte(str)[0]
}

// Return the key ring of the current process.
func ProcessKeyring() Keyring {
	return -2
}

func (keyring Keyring) LoadRsaPrivateKey(name string, key *rsa.PrivateKey) (RsaKey, error) {
	serial, err := keyring.LoadPrivateKey(name, key)
	if err != nil {
		return RsaKey{}, fmt.Errorf("error loading private key: %w", err)
	}

	return RsaKey{serial}, nil
}

func (keyring Keyring) LoadEcdsaPrivateKey(name string, key *ecdsa.PrivateKey) (EcdsaKey, error) {
	keySize := key.Params().BitSize
	serial, err := keyring.LoadPrivateKey(name, key)
	if err != nil {
		return EcdsaKey{}, fmt.Errorf("error loading private key: %w", err)
	}

	ecdsaKey := EcdsaKey{serial, keySize}

	return ecdsaKey, nil
}

func (keyring Keyring) LoadPrivateKey(name string, key crypto.PrivateKey) (KeySerial, error) {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return 0, fmt.Errorf("error PCKS8-encoding private key: %w", err)
	}

	serial, err := syscall_add_key_asym(keyring, name, pkcs8)
	if err != nil {
		return 0, fmt.Errorf("error in add_key syscall: %w", err)
	}

	return serial, nil
}

func (key KeySerial) SignPrehashed(info, digest, signature []byte) error {
	err := syscall_keyctl_pkey_sign(key, info, digest, signature)
	if err != nil {
		return fmt.Errorf("error in keyctl pkey_sign syscall: %w", err)
	}

	return nil
}

func (key KeySerial) VerifyPrehashed(info, digest, signature []byte) error {
	err := syscall_keyctl_pkey_verify(key, info, digest, signature)
	if err != nil {
		return fmt.Errorf("error in keyctl pkey_verify syscall: %w", err)
	}

	return nil
}
