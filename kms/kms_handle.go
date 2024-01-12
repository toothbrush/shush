package kms

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/realestate-com-au/shush/awsmeta"
)

type kmsEncryptionContext map[string]string

// Structure encapsulating stuff common to encrypt and decrypt.
type KmsHandle struct {
	Client  *kms.Client
	Context kmsEncryptionContext
}

func NewHandle(region string, encryptionContextData []string) (*KmsHandle, error) {
	encryptionContext, err := parseEncryptionContext(encryptionContextData)
	if err != nil {
		return nil, fmt.Errorf("could not parse encryption context: %w", err)
	}

	if region == "" {
		region, err = awsmeta.GetRegion()
		if err != nil {
			return nil, fmt.Errorf("please specify region (--region or $AWS_DEFAULT_REGION)")
		}
	}

	conf, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("could not create AWS session: %w", err)
	}

	client := kms.NewFromConfig(conf)
	return &KmsHandle{
		Client:  client,
		Context: encryptionContext,
	}, nil
}

func parseEncryptionContext(contextStrings []string) (kmsEncryptionContext, error) {
	context := make(kmsEncryptionContext, len(contextStrings))
	for _, s := range contextStrings {
		parts := strings.SplitN(s, "=", 2)
		if len(parts) < 2 {
			return nil, fmt.Errorf("context must be provided in NAME=VALUE format")
		}
		context[parts[0]] = parts[1]
	}
	return context, nil
}

// Encrypt plaintext using specified key.
func (h *KmsHandle) Encrypt(plaintext string, keyID string) (string, error) {
	output, err := h.Client.Encrypt(context.TODO(), &kms.EncryptInput{
		KeyId:             &keyID,
		EncryptionContext: h.Context,
		Plaintext:         []byte(plaintext),
	})
	if err != nil {
		return "", fmt.Errorf("kms: failed to encrypt: %w", err)
	}

	return base64.StdEncoding.EncodeToString(output.CiphertextBlob), nil
}

// Decrypt ciphertext.
func (h *KmsHandle) Decrypt(ciphertext string) (string, string, error) {
	ciphertextBlob, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", "", fmt.Errorf("kms: failed base64 decoding: %w", err)
	}

	output, err := h.Client.Decrypt(context.TODO(), &kms.DecryptInput{
		EncryptionContext: h.Context,
		CiphertextBlob:    ciphertextBlob,
	})
	if err != nil {
		return "", "", fmt.Errorf("kms: failed to decrypt: %w", err)
	}

	keyId := ""
	if output.KeyId != nil {
		keyId = *output.KeyId
	}
	return string(output.Plaintext), keyId, nil
}
