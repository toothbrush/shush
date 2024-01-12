package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/realestate-com-au/shush/kms"
	"github.com/realestate-com-au/shush/sys"
	"github.com/urfave/cli/v2"
)

func main() {

	app := cli.NewApp()
	app.Name = "shush"
	app.Version = "1.5.4"
	app.Usage = "KMS encryption and decryption"

	app.Flags = []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "context",
			Aliases: []string{"C"},
			Usage:   "encryption context",
			EnvVars: []string{"KMS_ENCRYPTION_CONTEXT"},
		},
		&cli.StringFlag{
			Name:    "region",
			Usage:   "AWS region",
			EnvVars: []string{"AWS_DEFAULT_REGION"},
		},
	}

	app.Commands = []*cli.Command{
		{
			Name:  "encrypt",
			Usage: "Encrypt with a KMS key",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:    "trim",
					Aliases: []string{"t"},
					Usage:   "If set, remove leading and trailing whitespace from plaintext",
				},
			},
			Action: func(c *cli.Context) error {
				if c.Args().Len() == 0 {
					return fmt.Errorf("no encryption key specified")
				}
				key := c.Args().First()

				if !isValidUUID(key) && !isArn(key) {
					if !isAlias(key) {
						key = "alias/" + key
					}
				}

				handle, err := kms.NewHandle(
					c.String("region"),
					c.StringSlice("context"),
				)
				if err != nil {
					sys.Abort(sys.UsageError, err)
				}
				plaintext, err := sys.GetPayload(c.Args().Slice()[1:])
				if err != nil {
					sys.Abort(sys.UsageError, err)
				}
				if c.Bool("trim") {
					plaintext = strings.TrimSpace(plaintext)
				}
				ciphertext, err := handle.Encrypt(plaintext, key)
				if err != nil {
					sys.Abort(sys.KmsError, err)
				}
				fmt.Println(ciphertext)
			},
		},
		{
			Name:  "decrypt",
			Usage: "Decrypt KMS ciphertext",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "print-key",
					Usage: "Print the key instead of the deciphered text",
				},
			},
			Action: func(c *cli.Context) error {
				handle, err := kms.NewHandle(
					c.String("region"),
					c.StringSlice("context"),
				)
				if err != nil {
					sys.Abort(sys.UsageError, err)
				}
				ciphertext, err := sys.GetPayload(c.Args().Slice())
				if err != nil {
					sys.Abort(sys.UsageError, err)
				}
				plaintext, keyId, err := handle.Decrypt(ciphertext)
				if err != nil {
					sys.Abort(sys.KmsError, err)
				}
				if c.Bool("print-key") {
					fmt.Print(keyId)
				} else {
					fmt.Print(plaintext)
				}
			},
		},
		{
			Name:  "exec",
			Usage: "Execute a command",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "prefix",
					Usage: "environment variable prefix",
					Value: "KMS_ENCRYPTED_",
				},
			},
			Action: func(c *cli.Context) error {
				encryptedVarPrefix := c.String("prefix")
				foundEncrypted := false
				for _, e := range os.Environ() {
					if strings.HasPrefix(e, encryptedVarPrefix) {
						foundEncrypted = true
						break
					}
				}
				if foundEncrypted {
					handle, err := kms.NewHandle(
						c.String("region"),
						c.StringSlice("context"),
					)
					if err != nil {
						return fmt.Errorf("shush: incorrect usage: %w", err)
					}
					for _, e := range os.Environ() {
						keyValuePair := strings.SplitN(e, "=", 2)
						key := keyValuePair[0]
						if strings.HasPrefix(key, encryptedVarPrefix) {
							ciphertext := keyValuePair[1]
							plaintextKey := key[len(encryptedVarPrefix):len(key)]
							plaintext, _, err := handle.Decrypt(ciphertext)
							if err != nil {
								sys.Abort(sys.KmsError, fmt.Sprintf("cannot decrypt $%s; %s\n", key, err))
							}
							os.Setenv(plaintextKey, plaintext)
						}
					}
				}
				sys.ExecCommand(c.Args().Slice())
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		sys.Abort(status int, message interface{})
		log.Fatal(err)
	}
}

func isValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}

func isArn(u string) bool {
	return strings.HasPrefix(u, "arn:aws:kms")
}

func isAlias(u string) bool {
	return strings.HasPrefix(u, "alias/")
}
