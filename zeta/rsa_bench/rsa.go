package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"log"
	"syscall"
	"unsafe"
)

type KeySerial int32
type Keyring int32
type KeyOps = uintptr

const (
	KEY_SPEC_PROCESS_KEYRING Keyring = -2
	KEYCTL_PKEY_SIGN         KeyOps  = 27
	KEYCTL_PKEY_VERIFY       KeyOps  = 28
)

var (
	keyTypeAsym = []byte("asymmetric\x00")
	sha256pkcs1 = []byte("enc=pkcs1 hash=sha256\x00")
)

func (keyring Keyring) LoadAsym(desc string, payload []byte) (KeySerial, error) {
	cdesc := []byte(desc + "\x00")
	serial, _, errno := syscall.Syscall6(
		syscall.SYS_ADD_KEY,
		uintptr(unsafe.Pointer(&keyTypeAsym[0])),
		uintptr(unsafe.Pointer(&cdesc[0])),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(keyring),
		uintptr(0),
	)
	if errno == 0 {
		return KeySerial(serial), nil
	}

	return KeySerial(serial), errno
}

type pkeyParams struct {
	key_id         KeySerial
	in_len         uint32
	out_or_in2_len uint32
	__spare        [7]uint32
}

func (key KeySerial) Sign(info, digest, signature []byte) error {
	var params pkeyParams
	params.key_id = key
	params.in_len = uint32(len(digest))
	params.out_or_in2_len = uint32(len(signature))

	_, _, errno := syscall.Syscall6(
		syscall.SYS_KEYCTL, KEYCTL_PKEY_SIGN,
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Pointer(&info[0])),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(unsafe.Pointer(&signature[0])),
		uintptr(0),
	)
	if errno == 0 {
		return nil
	}

	return errno
}

func (key KeySerial) Verify(info, digest, signature []byte) error {
	var params pkeyParams
	params.key_id = key
	params.in_len = uint32(len(digest))
	params.out_or_in2_len = uint32(len(signature))

	_, _, errno := syscall.Syscall6(
		syscall.SYS_KEYCTL, KEYCTL_PKEY_VERIFY,
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Pointer(&info[0])),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(unsafe.Pointer(&signature[0])),
		uintptr(0),
	)
	if errno == 0 {
		return nil
	}

	return errno
}

func loadKeyToKernel(key crypto.PrivateKey) KeySerial {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatalf("failed to serialize the private key to PKCS8 blob: %v", err)
	}

	serial, err := KEY_SPEC_PROCESS_KEYRING.LoadAsym("test rsa key", pkcs8)
	if err != nil {
		log.Fatalf("failed to load the private key into the keyring: %v", err)
	}

	log.Printf("Loaded key to the kernel with ID: %v", serial)

	return serial
}

func main() {
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

	err = keyInKernel.Sign(sha256pkcs1, digest[:], signature[:])
	if err != nil {
		log.Fatalf("failed to sign the digest: %v", err)
	}
	log.Printf("Signature from Kernel: %x...", signature[:10])

	err = keyInKernel.Verify(sha256pkcs1, digest[:], signature[:])
	if err != nil {
		log.Fatalf("failed to verify the digest: %v", err)
	}
	log.Printf("Valid signature from Kernel: %v", err == nil)

	err = rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, digest[:], signature[:])
	log.Printf("Valid signature from Go: %v", err == nil)
	if err != nil {
		log.Fatalf("failed to verify the signature: %v", err)
	}
}
