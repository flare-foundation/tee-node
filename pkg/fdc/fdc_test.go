package fdc_test

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/fdc2"
	"github.com/flare-foundation/tee-node/pkg/fdc"
	"github.com/stretchr/testify/require"
)

func TestAbiEncodeDecodeFDCProveResponse(t *testing.T) {
	// Create a test response header
	originalResponseHeader := fdc2.IFdc2HubFdc2ResponseHeader{
		AttestationType:    [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		SourceId:           [32]byte{33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64},
		ThresholdBIPS:      7500, // 75%
		ProofOwner:         common.HexToAddress("0xfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed"),
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
	require.Equal(t, originalResponseHeader.ProofOwner, decodedResponseHeader.ProofOwner)
	require.Equal(t, originalResponseHeader.Cosigners, decodedResponseHeader.Cosigners)
	require.Equal(t, originalResponseHeader.CosignersThreshold, decodedResponseHeader.CosignersThreshold)
	require.Equal(t, originalResponseHeader.Timestamp, decodedResponseHeader.Timestamp)
}

func TestAbiEncodeDecodeFDCProveRequest(t *testing.T) {
	// Create a test attestation request
	originalAttestationRequest := fdc2.IFdc2HubFdc2AttestationRequest{
		Header: fdc2.IFdc2HubFdc2RequestHeader{
			AttestationType: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
			SourceId:        [32]byte{33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64},
			ThresholdBIPS:   7500, // 75%
			ProofOwner:      common.HexToAddress("0xfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed"),
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
	require.Equal(t, originalAttestationRequest.Header.ProofOwner, decodedAttestationRequest.Header.ProofOwner)
	require.Equal(t, originalAttestationRequest.RequestBody, decodedAttestationRequest.RequestBody)
}

func TestHashMessage(t *testing.T) {
	// Sample data for the header
	attestationType := [32]byte{1, 2, 3}
	sourceID := [32]byte{10, 11, 12}
	thresholdBIPS := uint16(9200)
	proofOwner := common.HexToAddress("0xfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed")
	cosigners := []common.Address{
		common.HexToAddress("0x1111111111111111111111111111111111111111"),
		common.HexToAddress("0x2222222222222222222222222222222222222222"),
	}
	cosignersThreshold := uint64(1)
	timestamp := uint64(1717171717)
	requestBody := []byte{0xde, 0xad, 0xbe, 0xef}
	responseBody := []byte{0xca, 0xfe, 0xba, 0xbe}

	// Input request
	req := fdc2.IFdc2HubFdc2AttestationRequest{
		Header: fdc2.IFdc2HubFdc2RequestHeader{
			AttestationType: attestationType,
			SourceId:        sourceID,
			ThresholdBIPS:   thresholdBIPS,
			ProofOwner:      proofOwner,
		},
		RequestBody: requestBody,
	}

	const chainID uint64 = 31337
	hash, encHeader, err := fdc.HashMessage(chainID, req, responseBody, cosigners, cosignersThreshold, timestamp)
	require.NoError(t, err)
	require.NotEmpty(t, hash)
	require.NotEmpty(t, encHeader)

	require.Greater(t, len(encHeader), 0)
	require.Equal(t, 32, len(hash.Bytes()))

	// Round-trip: the encoded response header must carry the request's ProofOwner.
	// This is the assertion that would have caught the prior MEDIUM-07 omission.
	decodedHeader, err := fdc.DecodeResponse(encHeader)
	require.NoError(t, err)
	require.Equal(t, proofOwner, decodedHeader.ProofOwner, "ProofOwner from the request header must be propagated into the response header")

	// Changing any input should result in a different hash
	req2 := req
	req2.RequestBody = []byte{0xaa, 0xbb, 0xcc}
	hash2, _, err := fdc.HashMessage(chainID, req2, responseBody, cosigners, cosignersThreshold, timestamp)
	require.NoError(t, err)
	require.NotEqual(t, hash, hash2, "Changing the request body should produce a different hash")

	// Test with empty cosigners
	hash3, _, err := fdc.HashMessage(chainID, req, responseBody, []common.Address{}, cosignersThreshold, timestamp)
	require.NoError(t, err)
	require.NotEqual(t, hash, hash3, "Changing the cosigners should produce a different hash")

	// Changing timestamp should change the hash
	hash4, _, err := fdc.HashMessage(chainID, req, responseBody, cosigners, cosignersThreshold, timestamp+1)
	require.NoError(t, err)
	require.NotEqual(t, hash, hash4, "Changing the timestamp should produce a different hash")

	// Changing responseBody should change the hash
	hash5, _, err := fdc.HashMessage(chainID, req, []byte{0x99, 0x98, 0x97}, cosigners, cosignersThreshold, timestamp)
	require.NoError(t, err)
	require.NotEqual(t, hash, hash5, "Changing the responseBody should produce a different hash")

	// Changing ProofOwner should change the hash — proves the field is inside
	// the signed payload, not just decorative.
	req6 := req
	req6.Header.ProofOwner = common.HexToAddress("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead")
	hash6, _, err := fdc.HashMessage(chainID, req6, responseBody, cosigners, cosignersThreshold, timestamp)
	require.NoError(t, err)
	require.NotEqual(t, hash, hash6, "Changing the proof owner should produce a different hash")

	// Changing chainID changes the hash — proves chainID is bound into the
	// SignedPayload envelope, preventing cross-chain replay.
	hash7, _, err := fdc.HashMessage(chainID+1, req, responseBody, cosigners, cosignersThreshold, timestamp)
	require.NoError(t, err)
	require.NotEqual(t, hash, hash7, "Changing the chainID should produce a different hash")
}

var digestMessageHash = common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")

// chainBoundPreimageHash mirrors Fdc2ProofVerification.toCosignersMessageHash
// independently of ChainBoundRelayPrefixedHash, so the two constructions must
// agree for the test to mean anything.
func chainBoundPreimageHash(t *testing.T, chainID uint64, messageHash common.Hash) common.Hash {
	t.Helper()

	// big.Int keeps the word construction independent of the helper's binary.BigEndian
	word := common.LeftPadBytes(new(big.Int).SetUint64(chainID).Bytes(), 32)
	preimage := append(word, common.FromHex("0x010000000000")...)
	preimage = append(preimage, messageHash.Bytes()...)
	require.Len(t, preimage, 70)

	return crypto.Keccak256Hash(preimage)
}

func TestChainBoundRelayPrefixedHash(t *testing.T) {
	t.Parallel()

	t.Run("matches the contract digest", func(t *testing.T) {
		t.Parallel()

		// evaluated on the EVM from Fdc2ProofVerification.toCosignersMessageHash:
		// keccak256(bytes.concat(bytes32(block.chainid), hex"010000000000", _messageHash))
		// with block.chainid 14 and digestMessageHash. Must stay identical to the
		// value the relay client pins for the same inputs.
		golden := common.HexToHash("0x452299ddddf6ab40ffe351e672e786ab155216ed644c7eb9cfbcac88efd027f4")

		require.Equal(t, golden, fdc.ChainBoundRelayPrefixedHash(14, digestMessageHash))
		require.Equal(t, golden, chainBoundPreimageHash(t, 14, digestMessageHash))
	})

	t.Run("binds the chain", func(t *testing.T) {
		t.Parallel()

		require.NotEqual(t,
			fdc.ChainBoundRelayPrefixedHash(14, digestMessageHash),
			fdc.ChainBoundRelayPrefixedHash(16, digestMessageHash),
		)
	})

	t.Run("differs from the retired unbound form", func(t *testing.T) {
		t.Parallel()

		require.NotEqual(t,
			fdc.RelayPrefixedHash(digestMessageHash),
			fdc.ChainBoundRelayPrefixedHash(14, digestMessageHash),
		)
	})
}
