package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"kmstool_enclave_cli_go/nsm"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type Decrypt struct {
	enclaveCommandExecutor
	ciphertext          string
	keyId               string
	encryptionAlgorithm string
}

func NewDecryptCommand() *Decrypt {
	grc := &Decrypt{
		enclaveCommandExecutor: enclaveCommandExecutor{
			fs: flag.NewFlagSet("decrypt", flag.ContinueOnError),
		},
	}
	grc.addCommonFlags()
	grc.fs.StringVar(&grc.ciphertext, "ciphertext", "", "base64-encoded ciphertext that need to decrypt")
	grc.fs.StringVar(&grc.ciphertext, "key-id", "", "decrypt key id (for symmetric keys, is optional)")
	grc.fs.StringVar(&grc.ciphertext, "encryption-algorithm", "", "encryption algorithm for ciphertext")
	return grc
}

func (d *Decrypt) Name() string {
	return d.fs.Name()
}

func (d *Decrypt) Init(args []string) error {
	err := d.fs.Parse(args)
	if err != nil {
		return err
	}

	if err := d.checkExecutorConfiguration(); err != nil {
		return err
	}

	if d.ciphertext == "" {
		return fmt.Errorf("--ciphertext must be set")
	}

	return nil
}

func (d *Decrypt) Run() error {
	if err := d.initExecutor(); err != nil {
		return fmt.Errorf("failed to init command executotr: %w", err)
	}

	request, err := d.prepareGenerateRandomRequest()
	if err != nil {
		return fmt.Errorf("failed to prepare generate random request: %w", err)
	}

	result, err := d.kmsClient.Decrypt(d.context, request)
	if err != nil {
		return fmt.Errorf("failed to call Decrypt: %w", err)
	}

	plaintext, err := d.decryptKmsResponse(result.CiphertextForRecipient)
	if err != nil {
		return fmt.Errorf("failed to decrypt KMS response: %w", err)
	}

	fmt.Println("Decrypted response:", plaintext)

	return nil
}

func (d *Decrypt) prepareGenerateRandomRequest() (*kms.DecryptInput, error) {
	attestationDocument, err := nsm.AttestationRequest(d.publicKey)
	if err != nil {
		fmt.Println("Failed to get attestation document:", err)
		return nil, err
	}

	ciphertextBytes, err := base64.StdEncoding.DecodeString(d.ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 cihertext into bytes: %w", err)
	}

	recipientInfo := types.RecipientInfo{
		KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256,
		AttestationDocument:    attestationDocument,
	}

	input := &kms.DecryptInput{
		CiphertextBlob: ciphertextBytes,
		Recipient:      &recipientInfo,
	}

	if d.keyId != "" {
		input.KeyId = &d.keyId
	}
	if d.encryptionAlgorithm != "" {
		input.EncryptionAlgorithm = types.EncryptionAlgorithmSpec(d.encryptionAlgorithm)
	}

	return input, nil
}
