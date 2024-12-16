package cms

import (
	"bytes"
	"encoding/asn1"
	"fmt"
)

const (
	ENVELOPED_DATA_VERSION           = 2
	ENVELOPED_DATA_RECIPIENT_VERSION = 2
)

// CMSEnvelopedData represents the parsed CMS enveloped data structure
type CMSEnvelopedData struct {
	ContentType asn1.ObjectIdentifier
	Content     envelopedDataContent `asn1:"explicit,tag:0"`
}

// Wrapper to handle the explicit tagging
type envelopedDataContent struct {
	Version          int
	RecipientInfos   []KeyTransRecipientInfo `asn1:"set"`
	EncryptedContent EncryptedContentInfo
}

// KeyTransRecipientInfo represents the KeyTransRecipientInfo structure
type KeyTransRecipientInfo struct {
	Version                int
	SubjectKeyIdentifier   []byte `asn1:"tag:0,context,implicit"` // Changed this line
	KeyEncryptionAlgorithm AlgorithmIdentifier
	EncryptedKey           []byte
}

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type EncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,explicit,optional"`
}

func ParseCMSEnvelopedData(inBer []byte) (cipherkey, iv, ciphertext []byte, err error) {
	// Convert BER to DER before parsing
	inDer, err := ber2der(inBer)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to convert BER to DER: %w", err)
	}

	var envelopedData CMSEnvelopedData

	// Decode the DER-encoded data
	rest, err := asn1.Unmarshal(inDer, &envelopedData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal CMS data: %w", err)
	}
	if len(rest) > 0 {
		return nil, nil, nil, fmt.Errorf("trailing data after CMS structure")
	}

	// Verify content type is pkcs7-enveloped
	// OID for pkcs7-enveloped: 1.2.840.113549.1.7.3
	expectedOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	if !envelopedData.ContentType.Equal(expectedOID) {
		return nil, nil, nil, fmt.Errorf("unexpected content type")
	}

	// Verify version
	if envelopedData.Content.Version != ENVELOPED_DATA_VERSION {
		return nil, nil, nil, fmt.Errorf("unsupported enveloped data version")
	}

	// We expect exactly one recipient
	if len(envelopedData.Content.RecipientInfos) != 1 {
		return nil, nil, nil, fmt.Errorf("expected exactly one recipient info")
	}

	recipientInfo := envelopedData.Content.RecipientInfos[0]

	// Extract the cipher key (encrypted with RSA-OAEP)
	cipherkey = recipientInfo.EncryptedKey

	// Extract IV and ciphertext from EncryptedContentInfo
	encryptedContent := envelopedData.Content.EncryptedContent

	// The IV should be in the algorithm parameters of ContentEncryptionAlgorithm
	// For AES-256-CBC, it should be an OCTET STRING
	var ivBytes asn1.RawValue
	if _, err := asn1.Unmarshal(encryptedContent.ContentEncryptionAlgorithm.Parameters.FullBytes, &ivBytes); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to extract IV: %w", err)
	}
	iv = ivBytes.Bytes

	// Extract the ciphertext
	ciphertext = encryptedContent.EncryptedContent

	return cipherkey, iv, ciphertext, nil
}

// ber2der attempts to convert BER encoded data to DER encoding
func ber2der(ber []byte) ([]byte, error) {
	if len(ber) == 0 {
		return nil, fmt.Errorf("input bytes empty")
	}

	// Check if the input is already DER encoded
	if !isIndefiniteLength(ber) {
		return ber, nil
	}

	// Parse the BER data
	reader := bytes.NewReader(ber)
	der, err := convertBERtoDER(reader)
	if err != nil {
		return nil, err
	}

	return der, nil
}

func isIndefiniteLength(data []byte) bool {
	if len(data) < 3 {
		return false
	}
	// Check if length bytes indicate indefinite form (0x80)
	return data[1] == 0x80
}

func convertBERtoDER(reader *bytes.Reader) ([]byte, error) {
	tag, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	length, isIndefinite, err := readLength(reader)
	if err != nil {
		return nil, err
	}

	if !isIndefinite {
		// Definite length - copy as is
		content := make([]byte, length)
		_, err = reader.Read(content)
		if err != nil {
			return nil, err
		}
		return append([]byte{tag}, append(encodeLength(length), content...)...), nil
	}

	// Handle indefinite length
	var content []byte
	for {
		// Check for EOC (End of Content)
		b1, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		b2, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}

		if b1 == 0x00 && b2 == 0x00 {
			// Found EOC
			break
		}

		// Not EOC, push back bytes and continue reading
		reader.UnreadByte()
		reader.UnreadByte()

		// Convert nested content
		chunk, err := convertBERtoDER(reader)
		if err != nil {
			return nil, err
		}
		content = append(content, chunk...)
	}

	// Create DER encoding
	return append([]byte{tag}, append(encodeLength(len(content)), content...)...), nil
}

func readLength(reader *bytes.Reader) (length int, isIndefinite bool, err error) {
	b, err := reader.ReadByte()
	if err != nil {
		return 0, false, err
	}

	if b == 0x80 {
		return 0, true, nil
	}

	if b < 0x80 {
		return int(b), false, nil
	}

	numBytes := int(b & 0x7f)
	length = 0
	for i := 0; i < numBytes; i++ {
		b, err = reader.ReadByte()
		if err != nil {
			return 0, false, err
		}
		length = length<<8 | int(b)
	}
	return length, false, nil
}

func encodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}

	// Calculate number of bytes needed
	numBytes := 1
	for temp := length; temp > 0xff; temp >>= 8 {
		numBytes++
	}

	// Encode length
	result := make([]byte, numBytes+1)
	result[0] = byte(0x80 | numBytes)
	for i := numBytes; i > 0; i-- {
		result[i] = byte(length & 0xff)
		length >>= 8
	}
	return result
}
