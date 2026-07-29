package fdc

import (
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	csigning "github.com/flare-foundation/go-flare-common/pkg/signing"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/fdc2"
)

// ProveResponse represents the response structure for F_FDC2 PROVE opCommand.
type ProveResponse struct {
	ResponseHeader         hexutil.Bytes   `json:"responseHeader"`
	RequestBody            hexutil.Bytes   `json:"requestBody"`
	ResponseBody           hexutil.Bytes   `json:"responseBody"`
	TEESignature           hexutil.Bytes   `json:"teeSignature"`
	CosignerSignatures     []hexutil.Bytes `json:"cosignerSignatures"`
	DataProviderSignatures hexutil.Bytes   `json:"dataProviderSignatures"`
}

// EncodeRequest encodes an FDC2 attestation request to bytes.
func EncodeRequest(req fdc2.IFdc2HubFdc2AttestationRequest) (hexutil.Bytes, error) {
	return structs.Encode(fdc2.AttestationRequestArg, &req)
}

// DecodeRequest decodes bytes into an FDC2 attestation request.
func DecodeRequest(data []byte) (fdc2.IFdc2HubFdc2AttestationRequest, error) {
	var req fdc2.IFdc2HubFdc2AttestationRequest
	err := structs.DecodeTo(fdc2.AttestationRequestArg, data, &req)
	if err != nil {
		return fdc2.IFdc2HubFdc2AttestationRequest{}, err
	}
	return req, nil
}

// EncodeResponseHeader encodes an FDC2 response header to bytes.
func EncodeResponseHeader(header fdc2.IFdc2HubFdc2ResponseHeader) (hexutil.Bytes, error) {
	return structs.Encode(fdc2.ResponseHeaderArg, &header)
}

// DecodeResponse decodes bytes into an FDC2 response header.
func DecodeResponse(data []byte) (fdc2.IFdc2HubFdc2ResponseHeader, error) {
	var header fdc2.IFdc2HubFdc2ResponseHeader
	err := structs.DecodeTo(fdc2.ResponseHeaderArg, data, &header)
	if err != nil {
		return fdc2.IFdc2HubFdc2ResponseHeader{}, err
	}
	return header, nil
}

// relayDirectSigningPrefix matches the on-chain Relay Mode-2 message header
// for protocolId=1 (direct message signing): 1B protocolId || 4B
// votingRoundId || 1B isSecureRandom, all zeros except the leading 0x01.
// It mirrors the bytes Verification.toCosignersMessageHash prepends and
// must stay in sync with Relay.sol's MESSAGE_BYTES layout.
var relayDirectSigningPrefix = []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}

// RelayPrefixedHash returns keccak256(0x010000000000 || messageHash) — the
// inner hash that both cosigner signatures (Verification.toCosignersMessageHash)
// and signing-policy data-provider signatures (Relay.relay() Mode 2,
// protocolId=1) are recovered against. eth_sign-wrap this value before
// signing or recovering. Returns a 32-byte hash.
//
// The TEE's own signature path (Verification._verifyTeeSignature) recovers
// against the bare messageHash, so do not use this helper there.
func RelayPrefixedHash(messageHash common.Hash) common.Hash {
	buf := make([]byte, 0, len(relayDirectSigningPrefix)+32)
	buf = append(buf, relayDirectSigningPrefix...)
	buf = append(buf, messageHash[:]...)
	return crypto.Keccak256Hash(buf)
}

// HashMessage returns the SignedPayload preimage the on-chain Verification
// facet recovers FDC2 signatures against:
//
//	signing.Payload{signing.FDC2, chainID, keccak256(abi.encode(
//	    keccak256(abi.encode(header)),
//	    keccak256(abi.encode(requestBody)),
//	    keccak256(abi.encode(responseBody)),
//	))}.Hash()
//
// The encoded header is returned alongside so callers can embed it verbatim
// in the proof response.
func HashMessage(
	chainID uint64,
	req fdc2.IFdc2HubFdc2AttestationRequest,
	responseBody []byte,
	cosigners []common.Address,
	cosignersThreshold uint64,
	timestamp uint64,
) (common.Hash, hexutil.Bytes, error) {
	header := fdc2.IFdc2HubFdc2ResponseHeader{
		AttestationType:    req.Header.AttestationType,
		SourceId:           req.Header.SourceId,
		ThresholdBIPS:      req.Header.ThresholdBIPS,
		ProofOwner:         req.Header.ProofOwner,
		Cosigners:          cosigners,
		CosignersThreshold: cosignersThreshold,
		Timestamp:          timestamp,
	}

	encHeader, err := EncodeResponseHeader(header)
	if err != nil {
		return common.Hash{}, nil, err
	}

	headerHash := crypto.Keccak256Hash(encHeader)
	requestBodyHash := crypto.Keccak256Hash(req.RequestBody)
	responseBodyHash := crypto.Keccak256Hash(responseBody)

	bytes32Ty, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return common.Hash{}, nil, err
	}
	innerEnc, err := abi.Arguments{
		{Type: bytes32Ty},
		{Type: bytes32Ty},
		{Type: bytes32Ty},
	}.Pack([32]byte(headerHash), [32]byte(requestBodyHash), [32]byte(responseBodyHash))
	if err != nil {
		return common.Hash{}, nil, err
	}
	dataHash := crypto.Keccak256Hash(innerEnc)

	messageHash, err := csigning.NewPayload(csigning.FDC2, chainID, dataHash).Hash()
	if err != nil {
		return common.Hash{}, nil, err
	}
	return messageHash, encHeader, nil
}
