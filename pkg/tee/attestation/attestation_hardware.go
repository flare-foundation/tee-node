package attestation

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/proto/attest"
)

func CreateHardwareAttestation(nonce []byte) (*attest.Attestation, error) {
	var attestOpts client.AttestOpts
	attestOpts.Nonce = nonce

	// Create TDX quote provider
	tdxDevice, err := client.CreateTdxQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create TDX quote provider: %w", err)
	}
	attestOpts.TEEDevice = tdxDevice
	defer tdxDevice.Close()

	println("TDX device opened successfully: ")
	fmt.Println(tdxDevice)

	// Try to open the TPM device
	rwc, err := os.OpenFile("/dev/tpm0", os.O_RDWR, 0)
	if err != nil {
		// If /dev/tpm0 fails, try /dev/tpmrm0
		rwc, err = os.OpenFile("/dev/tpmrm0", os.O_RDWR, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to open TPM device: %w", err)
		}
	}
	defer rwc.Close()

	println("TPM device opened successfully: ", rwc.Name())

	// Create attestation key
	ak, err := client.AttestationKeyECC(rwc)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation key: %w", err)
	}
	defer ak.Close()

	fmt.Printf("Attestation key created successfully: %v", ak.PublicArea().NameAlg.String())

	// Create attestation with TDX device
	attestation, err := ak.Attest(attestOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to attest: %w", err)
	}

	fmt.Printf("Attestation successful: %+v\n", attestation)

	return attestation, nil
}

// Using GOB encoding (binary format, Go-specific)
func EncodeAttestationGob(att *attest.Attestation) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(att)
	return buf.Bytes(), err
}

func DecodeAttestationGob(data []byte) (*attest.Attestation, error) {
	att := &attest.Attestation{}
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(att)
	return att, err
}

// Using JSON encoding (text format, more portable)
func EncodeAttestationJSON(att *attest.Attestation) (string, error) {
	data, err := json.Marshal(att)
	return string(data), err
}

func DecodeAttestationJSON(data string) (*attest.Attestation, error) {
	att := &attest.Attestation{}
	err := json.Unmarshal([]byte(data), att)
	return att, err
}
