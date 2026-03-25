package fdc

import (
	"bytes"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/connector"
)

// ProveResponse represents the response structure for F_FDC2 PROVE opCommand.
type ProveResponse struct {
	ResponseHeader         hexutil.Bytes
	RequestBody            hexutil.Bytes
	ResponseBody           hexutil.Bytes
	TEESignature           hexutil.Bytes
	CosignerSignatures     []hexutil.Bytes
	DataProviderSignatures hexutil.Bytes
}

// EncodeRequest encodes an FDC2 attestation request to bytes.
func EncodeRequest(req connector.IFdc2HubFdc2AttestationRequest) (hexutil.Bytes, error) {
	return structs.Encode(connector.AttestationRequestArg, &req)
}

// DecodeRequest decodes bytes into an FDC2 attestation request.
func DecodeRequest(data []byte) (connector.IFdc2HubFdc2AttestationRequest, error) {
	var req connector.IFdc2HubFdc2AttestationRequest
	err := structs.DecodeTo(connector.AttestationRequestArg, data, &req)
	if err != nil {
		return connector.IFdc2HubFdc2AttestationRequest{}, err
	}
	return req, nil
}

// EncodeResponseHeader encodes an FDC2 response header to bytes.
func EncodeResponseHeader(header connector.IFdc2HubFdc2ResponseHeader) (hexutil.Bytes, error) {
	return structs.Encode(connector.ResponseHeaderArg, &header)
}

// DecodeResponse decodes bytes into an FDC2 response header.
func DecodeResponse(data []byte) (connector.IFdc2HubFdc2ResponseHeader, error) {
	var header connector.IFdc2HubFdc2ResponseHeader
	err := structs.DecodeTo(connector.ResponseHeaderArg, data, &header)
	if err != nil {
		return connector.IFdc2HubFdc2ResponseHeader{}, err
	}
	return header, nil
}

// HashMessage creates a hash of the FDC message components.
func HashMessage(
	req connector.IFdc2HubFdc2AttestationRequest,
	responseBody []byte,
	cosigners []common.Address,
	cosignersThreshold uint64,
	timestamp uint64,
) (common.Hash, common.Hash, hexutil.Bytes, hexutil.Bytes, error) {
	header := connector.IFdc2HubFdc2ResponseHeader{
		AttestationType:    req.Header.AttestationType,
		SourceId:           req.Header.SourceId,
		ThresholdBIPS:      req.Header.ThresholdBIPS,
		Cosigners:          cosigners,
		CosignersThreshold: cosignersThreshold,
		Timestamp:          timestamp,
	}

	encHeader, err := EncodeResponseHeader(header)
	if err != nil {
		return common.Hash{}, common.Hash{}, nil, nil, err
	}

	headerHash := crypto.Keccak256(encHeader)
	reqBodyHash := crypto.Keccak256(req.RequestBody)
	resBodyHash := crypto.Keccak256(responseBody)

	msgHash := crypto.Keccak256Hash(headerHash, reqBodyHash, resBodyHash)

	buffer := bytes.NewBuffer(nil)
	buffer.WriteByte(1)           // 1 byte (protocolId=1)
	buffer.Write(make([]byte, 5)) // 4 bytes (votingRoundId=0), 1 byte (isSecureRandom=false)
	buffer.Write(msgHash[:])      // 32 bytes
	msgHashPrepended := buffer.Bytes()

	hashToBeSigned := crypto.Keccak256Hash(msgHashPrepended)

	return hashToBeSigned, msgHash, msgHashPrepended, encHeader, nil
}
