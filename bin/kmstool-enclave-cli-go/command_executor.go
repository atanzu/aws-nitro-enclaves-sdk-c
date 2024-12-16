package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"flag"
	"fmt"
	"kmstool_enclave_cli_go/cms"
	"net"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/mdlayher/vsock"
)

type enclaveCommandExecutor struct {
	fs              *flag.FlagSet
	region          string
	proxyPort       uint
	accessKeyId     string
	secretAccessKey string
	sessionToken    string
	privateKey      *rsa.PrivateKey
	publicKey       *rsa.PublicKey
	context         context.Context
	kmsClient       *kms.Client
}

func (c *enclaveCommandExecutor) addCommonFlags() {
	c.fs.StringVar(&c.region, "region", "us-east-1", "AWS region to use for KMS. Default: 'us-east-1'")
	c.fs.UintVar(&c.proxyPort, "proxy-port", 8000, "Connect to KMS proxy on PORT. Default: 8000")
	c.fs.StringVar(&c.accessKeyId, "aws-access-key-id", "", "AWS access key ID")
	c.fs.StringVar(&c.secretAccessKey, "aws-secret-access-key", "", "AWS secret access key")
	c.fs.StringVar(&c.sessionToken, "aws-session-token", "", "Session token associated with the access key ID")
}

func (c *enclaveCommandExecutor) checkExecutorConfiguration() error {
	if c.accessKeyId == "" {
		return fmt.Errorf("--aws-access-key-id must be set")
	}

	if c.secretAccessKey == "" {
		return fmt.Errorf("--aws-secret-access-key must be set")
	}

	if c.sessionToken == "" {
		return fmt.Errorf("--aws-session-token must be set")
	}

	return nil
}

func (c *enclaveCommandExecutor) initExecutor() error {
	if err := c.createRsaKeyPair(); err != nil {
		return err
	}
	if err := c.createKmsClient(); err != nil {
		return err
	}
	return nil
}

func (c *enclaveCommandExecutor) createRsaKeyPair() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, DEFAULT_RSA_KEY_LENGTH)
	if err != nil {
		return err
	}

	c.privateKey = privateKey
	c.publicKey = &privateKey.PublicKey

	return nil
}

func (c *enclaveCommandExecutor) decryptKmsResponse(response []byte) ([]byte, error) {
	cipherkey, iv, ciphertext, err := cms.ParseCMSEnvelopedData(response)
	if err != nil {
		fmt.Println("Failed to parse CMS Enveloped Data:", err)
		return nil, err
	}

	aesKey, err := decryptRSAOAEP(c.privateKey, cipherkey)
	if err != nil {
		fmt.Println("Failed to decrypt symmetric key:", err)
		return nil, err
	}

	plaintextResult, err := decryptAES256CBC(ciphertext, aesKey, iv)
	if err != nil {
		fmt.Println("Failed to decrypt ciphertext:", err)
		return nil, err
	}

	return plaintextResult, nil
}

// decryptRSAOAEP decrypts the provided ciphertext using RSA-OAEP with SHA256
func decryptRSAOAEP(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}

	// Create a new hash for OAEP
	hash := sha256.New()

	// Decrypt the data using RSA-OAEP
	plaintext, err := rsa.DecryptOAEP(
		hash,       // hash function (SHA256)
		nil,        // random reader (not needed for decryption)
		privateKey, // private key
		ciphertext, // encrypted data
		nil,        // label (optional, we're not using it)
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

// decryptAES256CBC decrypts data using AES-256-CBC
func decryptAES256CBC(ciphertext, key, iv []byte) ([]byte, error) {
	// Validate inputs
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext is empty")
	}

	// Check key length (AES-256 requires 32 byte key)
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: expected 32 bytes, got %d", len(key))
	}

	// Check IV length (AES block size is 16 bytes)
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid IV length: expected %d bytes, got %d", aes.BlockSize, len(iv))
	}

	// Create new cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Check if ciphertext length is a multiple of block size
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	// Create decrypter
	mode := cipher.NewCBCDecrypter(block, iv)

	// Create output buffer
	plaintext := make([]byte, len(ciphertext))

	// Decrypt
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS#7 padding
	paddingLen := int(plaintext[len(plaintext)-1])
	if paddingLen > aes.BlockSize || paddingLen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	// Verify padding
	for i := len(plaintext) - paddingLen; i < len(plaintext); i++ {
		if plaintext[i] != byte(paddingLen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	// Return unpadded plaintext
	return plaintext[:len(plaintext)-paddingLen], nil
}

// vsockTransport implements http.RoundTripper for vsock connections
type vsockTransport struct {
	parentCID uint32
	port      uint32
}

// RoundTrip implements the http.RoundTripper interface
func (t *vsockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	conn, err := vsock.Dial(t.parentCID, t.port, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to dial vsock: %v", err)
	}
	defer conn.Close()

	// Convert the connection to an HTTP client
	httpConn := &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
	}

	return httpConn.Do(req)
}

func (c *enclaveCommandExecutor) createKmsClient() error {
	// Create custom HTTP client with vsock transport
	customHTTPClient := &http.Client{
		Transport: &vsockTransport{
			parentCID: DEFAULT_PARENT_CID,
			port:      uint32(c.proxyPort),
		},
	}

	c.context = context.Background()
	cfg, err := config.LoadDefaultConfig(c.context,
		config.WithCredentialsProvider(credentials.StaticCredentialsProvider{
			Value: aws.Credentials{
				AccessKeyID:     c.accessKeyId,
				SecretAccessKey: c.secretAccessKey,
				SessionToken:    c.sessionToken,
			},
		}),
		config.WithRegion(c.region),
		config.WithHTTPClient(customHTTPClient),
	)
	if err != nil {
		fmt.Println("Failed to create client configuration: %w", err)
		return err
	}

	c.kmsClient = kms.NewFromConfig(cfg)
	return nil
}
