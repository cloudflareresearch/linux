package signing_tool

import "fmt"

const (
	rsaKeySizeBits = 2048
	rsaSigLen      = rsaKeySizeBits / 8
	rsaDigestLen   = 32
)

type RsaKey struct {
	serial KeySerial
}

func RsaKeyFromSerial(serial KeySerial) RsaKey {
	return RsaKey{serial}
}

func (key RsaKey) Serial() int32 {
	return int32(key.serial)
}

func (key RsaKey) MakeSignatureBuffer() []byte {
	return make([]byte, rsaSigLen)
}

func (key RsaKey) SignRsaPrehashed(digest, signature []byte) ([]byte, error) {
	if err := checkSize(rsaDigestLen, len(digest)); err != nil {
		return nil, fmt.Errorf("invalid digest length: %w", err)
	}

	if err := checkSize(rsaSigLen, len(signature)); err != nil {
		return nil, fmt.Errorf("invalid signature buffer length: %w", err)
	}

	err := key.serial.SignPrehashed([]byte(signInfoRsa), digest, signature)
	if err != nil {
		return nil, fmt.Errorf("error signing: %w", err)
	}

	return signature, nil
}

func (key RsaKey) VerifyRsaPrehashed(digest, signature []byte) error {
	if err := checkSize(rsaDigestLen, len(digest)); err != nil {
		return fmt.Errorf("invalid digest length: %w", err)
	}

	return key.serial.VerifyPrehashed([]byte(signInfoRsa), digest, signature)
}
