package nsm

/*
#cgo LDFLAGS: -L. -lnsm
#include "nsm.h"
*/
import "C"
import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	NSM_RANDOM_REQ_SIZE          = 256 // Maximum size of random data from NSM
	RNDADDTOENTCNT               = 0x40045201
	NSM_MAX_ATTESTATION_DOC_SIZE = 16384
)

func SeedEntropy(numBytes uint64) error {
	// Initialize NSM
	nsmFd := C.nsm_lib_init()
	if nsmFd < 0 {
		return fmt.Errorf("failed to initialize NSM library")
	}
	defer C.nsm_lib_exit(nsmFd)

	// Open /dev/random
	devFd, err := os.OpenFile("/dev/random", os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open /dev/random: %w", err)
	}
	defer devFd.Close()

	var count uint64
	for count != numBytes {
		// Calculate buffer size for this iteration
		bufLen := NSM_RANDOM_REQ_SIZE
		if remaining := numBytes - count; remaining < uint64(bufLen) {
			bufLen = int(remaining)
		}

		// Prepare buffer for random data
		buf := make([]byte, bufLen)
		cBufLen := C.uintptr_t(bufLen)

		// Get random data from NSM
		if rc := C.nsm_get_random(nsmFd, (*C.uint8_t)(&buf[0]), &cBufLen); rc != 0 {
			return fmt.Errorf("failed to get random data from NSM")
		}

		// Check if we got any data
		if cBufLen == 0 {
			return fmt.Errorf("NSM returned zero entropy")
		}

		// Write to /dev/random
		n, err := devFd.Write(buf[:cBufLen])
		if err != nil {
			return fmt.Errorf("failed to write to /dev/random: %w", err)
		}
		if n != int(cBufLen) {
			return fmt.Errorf("incomplete write to /dev/random: wrote %d of %d bytes", n, cBufLen)
		}

		// Update entropy count
		bits := uint32(cBufLen * 8)
		_, _, errno := syscall.Syscall(
			syscall.SYS_IOCTL,
			uintptr(devFd.Fd()),
			uintptr(RNDADDTOENTCNT),
			uintptr(unsafe.Pointer(&bits)),
		)
		if errno != 0 {
			return fmt.Errorf("failed to update entropy count: %w", errno)
		}

		count += uint64(cBufLen)
	}

	return nil
}

// AttestationRequest generates attestation data using the provided RSA public key
func AttestationRequest(publicKey *rsa.PublicKey) ([]byte, error) {
	// Initialize NSM
	nsmFd := C.nsm_lib_init()
	if nsmFd < 0 {
		return nil, fmt.Errorf("failed to initialize NSM library")
	}
	defer C.nsm_lib_exit(nsmFd)

	// Marshal the public key to DER format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Prepare the attestation document buffer
	attDoc := make([]byte, NSM_MAX_ATTESTATION_DOC_SIZE)
	attDocLen := C.uint32_t(NSM_MAX_ATTESTATION_DOC_SIZE)

	// Call nsm_get_attestation_doc
	rc := C.nsm_get_attestation_doc(
		nsmFd,
		nil,                           // user_data
		0,                             // user_data_len
		nil,                           // nonce_data
		0,                             // nonce_len
		(*C.uint8_t)(&pubKeyBytes[0]), // pub_key_data
		C.uint32_t(len(pubKeyBytes)),  // pub_key_len
		(*C.uint8_t)(&attDoc[0]),      // att_doc_data
		&attDocLen,                    // att_doc_len
	)

	if rc != 0 {
		return nil, fmt.Errorf("failed to get attestation document: error code %d", rc)
	}

	// Return only the filled portion of the attestation document
	return attDoc[:attDocLen], nil
}
