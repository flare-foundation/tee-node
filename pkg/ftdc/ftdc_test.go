package ftdc_test

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/connector"
	"github.com/flare-foundation/tee-node/pkg/ftdc"
	"github.com/stretchr/testify/require"
)

func TestAbiEncodeDecodeFTDCProveResponse(t *testing.T) {
	// Create a test response header
	originalResponseHeader := connector.IFtdcHubFtdcResponseHeader{
		AttestationType:    [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		SourceId:           [32]byte{33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64},
		ThresholdBIPS:      7500, // 75%
		Cosigners:          []common.Address{common.HexToAddress("0x1234567890123456789012345678901234567890"), common.HexToAddress("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")},
		CosignersThreshold: 2,
		Timestamp:          1234567890,
	}

	// Encode the response header first
	encoded, err := ftdc.EncodeResponseHeader(originalResponseHeader)
	require.NoError(t, err)
	require.NotNil(t, encoded)

	// Decode the encoded data
	decodedResponseHeader, err := ftdc.DecodeResponse(encoded)
	require.NoError(t, err)

	// Verify all fields match the original
	require.Equal(t, originalResponseHeader.AttestationType, decodedResponseHeader.AttestationType)
	require.Equal(t, originalResponseHeader.SourceId, decodedResponseHeader.SourceId)
	require.Equal(t, originalResponseHeader.ThresholdBIPS, decodedResponseHeader.ThresholdBIPS)
	require.Equal(t, originalResponseHeader.Cosigners, decodedResponseHeader.Cosigners)
	require.Equal(t, originalResponseHeader.CosignersThreshold, decodedResponseHeader.CosignersThreshold)
	require.Equal(t, originalResponseHeader.Timestamp, decodedResponseHeader.Timestamp)
}

func TestAbiEncodeDecodeFTDCProveRequest(t *testing.T) {
	// Create a test attestation request
	originalAttestationRequest := connector.IFtdcHubFtdcAttestationRequest{
		Header: connector.IFtdcHubFtdcRequestHeader{
			AttestationType: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
			SourceId:        [32]byte{33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64},
			ThresholdBIPS:   7500, // 75%
		},
		RequestBody: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, // Sample request body
	}

	// Encode the attestation request
	encoded, err := ftdc.EncodeRequest(originalAttestationRequest)
	require.NoError(t, err)
	require.NotNil(t, encoded)

	// Decode the encoded data
	decodedAttestationRequest, err := ftdc.DecodeRequest(encoded)
	require.NoError(t, err)

	// Verify all fields match the original
	require.Equal(t, originalAttestationRequest.Header.AttestationType, decodedAttestationRequest.Header.AttestationType)
	require.Equal(t, originalAttestationRequest.Header.SourceId, decodedAttestationRequest.Header.SourceId)
	require.Equal(t, originalAttestationRequest.Header.ThresholdBIPS, decodedAttestationRequest.Header.ThresholdBIPS)
	require.Equal(t, originalAttestationRequest.RequestBody, decodedAttestationRequest.RequestBody)
}
