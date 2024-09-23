package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"github.com/urfave/cli/v2"

	"github.com/cryspen/signing_tool"
)

var (
	algName     string
	keyringName string
)

func main() {
	app := cli.App{
		Name: "signing_tool",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "algorithm name",
				Value:       "ecdsa-p256",
				Usage:       "Algorithm to use. Acceptable Values: rsa2048, ecdsa-p256, ecdsa-p384",
				Destination: &algName,
			},
			&cli.StringFlag{
				Name:        "keyring name",
				Value:       "user",
				Usage:       "Keyring to use. Acceptable Values: user-session, session, user, process",
				Destination: &keyringName,
			},
		},
		Commands: []*cli.Command{
			{
				Name:        "keygen",
				Description: "takes key name as first argument",
				Action:      exitify(keygen),
			},
			{
				Name:        "sign",
				Description: "takes key serial as first argument and hash as the second argument",
				Action:      exitify(sign),
			},
			{
				Name:        "verify",
				Description: "takes key name as first argument",
				Action:      exitify(verify),
			},
		},
	}

	app.Run(os.Args)
}

func exitify(f func(*cli.Context) error) func(*cli.Context) error {
	return func(cCtx *cli.Context) error {
		err := f(cCtx)
		if err != nil {
			return cli.Exit(err, 1)
		}

		return nil
	}
}

func keygen(cCtx *cli.Context) error {
	var (
		name    = cCtx.Args().Get(0)
		keyring signing_tool.Keyring
	)

	if name == "" {
		fmt.Println("please provide a name")
	}

	if keyringName == "user" {
		keyring = signing_tool.UserKeyring()
	} else if keyringName == "session" {
		keyring = signing_tool.SessionKeyring()
	} else if keyringName == "process" {
		keyring = signing_tool.ProcessKeyring()
	} else if keyringName == "user-session" {
		keyring = signing_tool.UserSessionKeyring()
	} else {
		return fmt.Errorf("invalid keyring name: %q", keyringName)
	}

	if algName == "rsa2048" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}

		rsa_key, err := keyring.LoadRsaPrivateKey(name, key)
		if err != nil {
			return err
		}

		fmt.Println("serial:", rsa_key.Serial())

	} else if algName == "ecdsa-p256" {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}

		serial, err := keyring.LoadPrivateKey(name, key)
		if err != nil {
			fmt.Println("wat1", err)
			return err
		}

		fmt.Println("serial:", serial)

	} else if algName == "ecdsa-p384" {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return err
		}

		serial, err := keyring.LoadPrivateKey(name, key)
		if err != nil {
			return err
		}

		fmt.Println("serial:", serial)
	} else {
		return fmt.Errorf("invalid algorithm name: %q", algName)
	}

	return nil
}

func sign(cCtx *cli.Context) error {
	var (
		serialString = cCtx.Args().Get(0)
		hashString   = cCtx.Args().Get(1)
		signature    []byte
	)

	serialI64, err := strconv.ParseInt(serialString, 10, 32)
	if err != nil {
		return fmt.Errorf("error parsing serial as number: %w", err)
	}

	serial := signing_tool.KeySerial(serialI64)

	hash, err := hex.DecodeString(hashString)
	if err != nil {
		return fmt.Errorf("error parsing hash as hex: %w", err)
	}

	if algName == "rsa2048" {
		key := signing_tool.RsaKeyFromSerial(serial)
		signatureBuffer := key.MakeSignatureBuffer()
		signature, err = key.SignRsaPrehashed(hash, signatureBuffer)
		if err != nil {
			return err
		}

	} else if algName == "ecdsa-p256" {
		key := signing_tool.EcdsaKeyFromSerialAndSize(serial, 256)
		if err != nil {
			return err
		}

		signatureBuffer := key.MakeSignatureBuffer()
		signature, err = key.SignPrehashed(hash, signatureBuffer)
		if err != nil {
			return err
		}

	} else if algName == "ecdsa-p384" {
		key := signing_tool.EcdsaKeyFromSerialAndSize(serial, 384)
		if err != nil {
			return err
		}

		signatureBuffer := key.MakeSignatureBuffer()
		signature, err = key.SignPrehashed(hash, signatureBuffer)
		if err != nil {
			return err
		}

	} else {
		return fmt.Errorf("invalid algorithm name: %q", algName)
	}

	fmt.Println("signature:", hex.EncodeToString(signature))

	return nil
}

func verify(cCtx *cli.Context) error {
	var (
		serialString    = cCtx.Args().Get(0)
		hashString      = cCtx.Args().Get(1)
		signatureString = cCtx.Args().Get(2)
	)

	serialI64, err := strconv.ParseInt(serialString, 10, 32)
	if err != nil {
		return fmt.Errorf("error parsing serial as number: %w", err)
	}

	serial := signing_tool.KeySerial(serialI64)

	hash, err := hex.DecodeString(hashString)
	if err != nil {
		return fmt.Errorf("error parsing hash as hex: %w", err)
	}

	signature, err := hex.DecodeString(signatureString)
	if err != nil {
		return fmt.Errorf("error parsing signature as hex: %w", err)
	}

	if algName == "rsa2048" {
		key := signing_tool.RsaKeyFromSerial(serial)
		if err := key.VerifyRsaPrehashed(hash, signature); err != nil {
			fmt.Println("verification error:", err)
		} else {
			fmt.Println("ok")
		}
	} else if algName == "ecdsa-p256" {
		key := signing_tool.EcdsaKeyFromSerialAndSize(serial, 256)
		if err != nil {
			return err
		}

		if err := key.VerifyPrehashed(hash, signature); err != nil {
			fmt.Println("verification error:", err)
		} else {
			fmt.Println("ok")
		}
	} else if algName == "ecdsa-p384" {
		key := signing_tool.EcdsaKeyFromSerialAndSize(serial, 384)
		if err != nil {
			return err
		}

		if err := key.VerifyPrehashed(hash, signature); err != nil {
			fmt.Println("verification error:", err)
		} else {
			fmt.Println("ok")
		}
	} else {
		return fmt.Errorf("invalid algorithm name: %q", algName)
	}

	return nil
}
