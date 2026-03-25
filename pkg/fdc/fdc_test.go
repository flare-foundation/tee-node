package fdc_test

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/connector"
	"github.com/flare-foundation/tee-node/pkg/fdc"
	"github.com/stretchr/testify/require"
)

func TestAbiEncodeDecodeFDCProveResponse(t *testing.T) {
	// Create a test response header
	originalResponseHeader := connector.IFdc2HubFdc2ResponseHeader{
		AttestationType:    [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		SourceId:           [32]byte{33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64},
		ThresholdBIPS:      7500, // 75%
		Cosigners:          []common.Address{common.HexToAddress("0x1234567890123456789012345678901234567890"), common.HexToAddress("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")},
		CosignersThreshold: 2,
		Timestamp:          1234567890,
	}

	// Encode the response header first
	encoded, err := fdc.EncodeResponseHeader(originalResponseHeader)
	require.NoError(t, err)
	require.NotNil(t, encoded)

	// Decode the encoded data
	decodedResponseHeader, err := fdc.DecodeResponse(encoded)
	require.NoError(t, err)

	// Verify all fields match the original
	require.Equal(t, originalResponseHeader.AttestationType, decodedResponseHeader.AttestationType)
	require.Equal(t, originalResponseHeader.SourceId, decodedResponseHeader.SourceId)
	require.Equal(t, originalResponseHeader.ThresholdBIPS, decodedResponseHeader.ThresholdBIPS)
	require.Equal(t, originalResponseHeader.Cosigners, decodedResponseHeader.Cosigners)
	require.Equal(t, originalResponseHeader.CosignersThreshold, decodedResponseHeader.CosignersThreshold)
	require.Equal(t, originalResponseHeader.Timestamp, decodedResponseHeader.Timestamp)
}

func TestAbiEncodeDecodeFDCProveRequest(t *testing.T) {
	// Create a test attestation request
	originalAttestationRequest := connector.IFdc2HubFdc2AttestationRequest{
		Header: connector.IFdc2HubFdc2RequestHeader{
			AttestationType: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
			SourceId:        [32]byte{33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64},
			ThresholdBIPS:   7500, // 75%
		},
		RequestBody: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, // Sample request body
	}

	// Encode the attestation request
	encoded, err := fdc.EncodeRequest(originalAttestationRequest)
	require.NoError(t, err)
	require.NotNil(t, encoded)

	// Decode the encoded data
	decodedAttestationRequest, err := fdc.DecodeRequest(encoded)
	require.NoError(t, err)

	// Verify all fields match the original
	require.Equal(t, originalAttestationRequest.Header.AttestationType, decodedAttestationRequest.Header.AttestationType)
	require.Equal(t, originalAttestationRequest.Header.SourceId, decodedAttestationRequest.Header.SourceId)
	require.Equal(t, originalAttestationRequest.Header.ThresholdBIPS, decodedAttestationRequest.Header.ThresholdBIPS)
	require.Equal(t, originalAttestationRequest.RequestBody, decodedAttestationRequest.RequestBody)
}

func TestHashMessage(t *testing.T) {
	// Sample data for the header
	attestationType := [32]byte{1, 2, 3}
	sourceID := [32]byte{10, 11, 12}
	thresholdBIPS := uint16(9200)
	cosigners := []common.Address{
		common.HexToAddress("0x1111111111111111111111111111111111111111"),
		common.HexToAddress("0x2222222222222222222222222222222222222222"),
	}
	cosignersThreshold := uint64(1)
	timestamp := uint64(1717171717)
	requestBody := []byte{0xde, 0xad, 0xbe, 0xef}
	responseBody := []byte{0xca, 0xfe, 0xba, 0xbe}

	// Input request
	req := connector.IFdc2HubFdc2AttestationRequest{
		Header: connector.IFdc2HubFdc2RequestHeader{
			AttestationType: attestationType,
			SourceId:        sourceID,
			ThresholdBIPS:   thresholdBIPS,
		},
		RequestBody: requestBody,
	}

	hash, _, msgHashPrepended, encHeader, err := fdc.HashMessage(req, responseBody, cosigners, cosignersThreshold, timestamp)
	require.NoError(t, err)
	require.NotEmpty(t, hash)
	require.NotEmpty(t, msgHashPrepended)
	require.NotEmpty(t, encHeader)

	require.Equal(t, 38, len(msgHashPrepended), "msgHashPrepended should be 38 bytes (1+5+32)")
	require.Greater(t, len(encHeader), 0)
	require.Equal(t, 32, len(hash.Bytes()))

	// Changing any input should result in a different hash
	req2 := req
	req2.RequestBody = []byte{0xaa, 0xbb, 0xcc}
	hash2, _, _, _, err := fdc.HashMessage(req2, responseBody, cosigners, cosignersThreshold, timestamp)
	require.NoError(t, err)
	require.NotEqual(t, hash, hash2, "Changing the request body should produce a different hash")

	// Test with empty cosigners
	hash3, _, _, _, err := fdc.HashMessage(req, responseBody, []common.Address{}, cosignersThreshold, timestamp)
	require.NoError(t, err)
	require.NotEqual(t, hash, hash3, "Changing the cosigners should produce a different hash")

	// Changing timestamp should change the hash
	hash4, _, _, _, err := fdc.HashMessage(req, responseBody, cosigners, cosignersThreshold, timestamp+1)
	require.NoError(t, err)
	require.NotEqual(t, hash, hash4, "Changing the timestamp should produce a different hash")

	// Changing responseBody should change the hash
	hash5, _, _, _, err := fdc.HashMessage(req, []byte{0x99, 0x98, 0x97}, cosigners, cosignersThreshold, timestamp)
	require.NoError(t, err)
	require.NotEqual(t, hash, hash5, "Changing the responseBody should produce a different hash")
}
