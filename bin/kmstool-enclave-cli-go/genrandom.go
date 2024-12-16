package main

import (
	"flag"
	"fmt"
	"kmstool_enclave_cli_go/nsm"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type GenerateRandom struct {
	enclaveCommandExecutor
	length int
}

func NewGenerateRandomCommand() *GenerateRandom {
	grc := &GenerateRandom{
		enclaveCommandExecutor: enclaveCommandExecutor{
			fs: flag.NewFlagSet("genrandom", flag.ContinueOnError),
		},
	}
	grc.addCommonFlags()
	grc.fs.IntVar(&grc.length, "length", -1, "The length of the random byte string")
	return grc
}

func (g *GenerateRandom) Name() string {
	return g.fs.Name()
}

func (g *GenerateRandom) Init(args []string) error {
	err := g.fs.Parse(args)
	if err != nil {
		return err
	}

	if err := g.checkExecutorConfiguration(); err != nil {
		return err
	}

	if g.length == -1 {
		return fmt.Errorf("--length must be set")
	}

	// Check if the length greater than 0 (KMS limit)
	if g.length <= 0 {
		return fmt.Errorf("--length must be greater than 0")
	}

	// Check if the length smaller or equal to 1024 (KMS limit)
	if g.length > 1024 {
		return fmt.Errorf("--length must be smaller or equal to 1024")
	}

	return nil
}

func (g *GenerateRandom) Run() error {
	if err := g.initExecutor(); err != nil {
		return fmt.Errorf("failed to init command executotr: %w", err)
	}

	request, err := g.prepareGenerateRandomRequest()
	if err != nil {
		return fmt.Errorf("failed to prepare generate random request: %w", err)
	}

	result, err := g.kmsClient.GenerateRandom(g.context, request)
	if err != nil {
		return fmt.Errorf("failed to generate random: %w", err)
	}

	plaintext, err := g.decryptKmsResponse(result.CiphertextForRecipient)
	if err != nil {
		return fmt.Errorf("failed to decrypt KMS response: %w", err)
	}

	fmt.Println("Result:", plaintext)

	return nil
}

func (g *GenerateRandom) prepareGenerateRandomRequest() (*kms.GenerateRandomInput, error) {
	attestationDocument, err := nsm.AttestationRequest(g.publicKey)
	if err != nil {
		fmt.Println("Failed to get attestation document:", err)
		return nil, err
	}

	recipientInfo := types.RecipientInfo{
		KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256,
		AttestationDocument:    attestationDocument,
	}

	randomLength := int32(g.length)
	return &kms.GenerateRandomInput{
		NumberOfBytes: &randomLength,
		Recipient:     &recipientInfo,
	}, nil
}
