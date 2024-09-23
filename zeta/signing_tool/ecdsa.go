package signing_tool

import "fmt"

const (
	ecdsaP256SigLen = 72
	ecdsaP384SigLen = 104
	ecdsaMaxSigLen  = ecdsaP384SigLen

	ecdsaP256DigestLen = 32
	ecdsaP384DigestLen = 48

	ecdsaInfo = "enc=x962 hash=sha256\x00"
)

type EcdsaKey struct {
	serial  KeySerial
	keySize int
}

func EcdsaKeyFromSerialAndSize(serial KeySerial, keySize int) EcdsaKey {
	return EcdsaKey{
		serial,
		keySize,
	}
}

func (key EcdsaKey) Serial() int32 {
	return int32(key.serial)
}

func (key EcdsaKey) MakeSignatureBuffer() []byte {
	if key.keySize == 256 {
		return make([]byte, ecdsaP256SigLen)
	} else if key.keySize == 384 {
		return make([]byte, ecdsaP384SigLen)
	} else {
		panic(fmt.Sprintf("unexpected ecdsa key size %v", key.keySize))
	}
}

func (key EcdsaKey) SignPrehashed(digest, signature []byte) ([]byte, error) {
	var (
		expectedDigestLen    int
		expectedSignatureLen int
	)

	if key.keySize == 384 {
		expectedDigestLen = ecdsaP384DigestLen
		expectedSignatureLen = ecdsaP384SigLen
	} else if key.keySize == 256 {
		expectedSignatureLen = ecdsaP256SigLen
		expectedDigestLen = ecdsaP256DigestLen
	}

	if err := checkSize(expectedSignatureLen, len(signature)); err != nil {
		return nil, fmt.Errorf("invalid signature buffer length: %w", err)
	}

	if err := checkSize(expectedDigestLen, len(digest)); err != nil {
		return nil, fmt.Errorf("invalid digest length: %w", err)
	}

	err := syscall_keyctl_pkey_sign(key.serial, []byte(ecdsaInfo), digest, signature)
	if err != nil {
		return nil, fmt.Errorf("error in keyctl pkey_sign syscall: %w", err)
	}

	n := uint64(signature[1]) + 2
	return signature[:n], nil
}

func (key EcdsaKey) VerifyPrehashed(digest, signature []byte) error {
	var expectedDigestLen int

	if key.keySize == 384 {
		expectedDigestLen = ecdsaP384DigestLen
	} else if key.keySize == 256 {
		expectedDigestLen = ecdsaP256DigestLen
	}

	if err := checkSize(expectedDigestLen, len(digest)); err != nil {
		return fmt.Errorf("invalid digest length: %w", err)
	}

	err := syscall_keyctl_pkey_verify(key.serial, []byte(ecdsaInfo), digest, signature)
	if err != nil {
		return fmt.Errorf("error in keyctl pkey_verify syscall: %w", err)
	}

	return nil
}
