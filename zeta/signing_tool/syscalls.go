package signing_tool

import (
	"syscall"
	"unsafe"
)

type keyOps = uintptr

const (
	KEYCTL_PKEY_SIGN   KeyOps = 27
	KEYCTL_PKEY_VERIFY KeyOps = 28

	keyTypeAsym   = "asymmetric\x00"
	signInfoRsa   = "enc=pkcs1 hash=sha256\x00"
	signInfoEcdsa = "enc=x962 hash=sha256\x00"
)

type pkeyParams struct {
	key_id         KeySerial
	in_len         uint32
	out_or_in2_len uint32
	__spare        [7]uint32
}

func syscall_add_key_asym(keyring Keyring, desc string, payload []byte) (KeySerial, error) {
	keyTypeAsym := []byte(keyTypeAsym)
	cdesc := []byte(desc + "\x00")

	serial, _, errno := syscall.Syscall6(
		syscall.SYS_ADD_KEY,
		uintptr(unsafe.Pointer(&keyTypeAsym[0])),
		uintptr(unsafe.Pointer(&cdesc[0])),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(keyring),
		uintptr(0))

	if errno == 0 {
		return KeySerial(serial), nil
	}

	return KeySerial(serial), errno
}

func syscall_keyctl_pkey_sign(key KeySerial, info, digest, signature []byte) error {
	params := pkeyParams{
		key_id:         key,
		in_len:         uint32(len(digest)),
		out_or_in2_len: uint32(len(signature)),
	}

	_, _, errno := syscall.Syscall6(
		syscall.SYS_KEYCTL, KEYCTL_PKEY_SIGN,
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Pointer(&info[0])),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(unsafe.Pointer(&signature[0])),
		uintptr(0),
	)

	if errno != 0 {
		return errno
	}

	return nil
}

func syscall_keyctl_pkey_verify(key KeySerial, info, digest, signature []byte) error {
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
