package types

import (
	"bytes"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/connector"
)

// FTDCProveResponse represents the response structure for FTDC prove operations.
type FTDCProveResponse struct {
	ResponseHeader         hexutil.Bytes
	RequestBody            hexutil.Bytes
	ResponseBody           hexutil.Bytes
	TEESignature           hexutil.Bytes
	CosignerSignatures     []hexutil.Bytes
	DataProviderSignatures hexutil.Bytes
}

// EncodeFTDCRequest encodes an FTDC attestation request to bytes.
func EncodeFTDCRequest(req connector.IFtdcHubFtdcAttestationRequest) (hexutil.Bytes, error) {
	return structs.Encode(connector.AttestationRequestArg, &req)
}

// DecodeFTDCRequest decodes bytes into an FTDC attestation request.
func DecodeFTDCRequest(data []byte) (connector.IFtdcHubFtdcAttestationRequest, error) {
	var req connector.IFtdcHubFtdcAttestationRequest
	err := structs.DecodeTo(connector.AttestationRequestArg, data, &req)
	if err != nil {
		return connector.IFtdcHubFtdcAttestationRequest{}, err
	}
	return req, nil
}

// EncodeFTDCResponseHeader encodes an FTDC response header to bytes.
func EncodeFTDCResponseHeader(header connector.IFtdcHubFtdcResponseHeader) (hexutil.Bytes, error) {
	return structs.Encode(connector.ResponseHeaderArg, &header)
}

// DecodeFTDCResponse decodes bytes into an FTDC response header.
func DecodeFTDCResponse(data []byte) (connector.IFtdcHubFtdcResponseHeader, error) {
	var header connector.IFtdcHubFtdcResponseHeader
	err := structs.DecodeTo(connector.ResponseHeaderArg, data, &header)
	if err != nil {
		return connector.IFtdcHubFtdcResponseHeader{}, err
	}
	return header, nil
}

// HashFTDCMessage creates a hash of the FTDC message components.
func HashFTDCMessage(req connector.IFtdcHubFtdcAttestationRequest, responseBody []byte, timestamp uint64) (common.Hash, hexutil.Bytes, hexutil.Bytes, error) {
	header := connector.IFtdcHubFtdcResponseHeader{
		AttestationType:    req.Header.AttestationType,
		SourceId:           req.Header.SourceId,
		ThresholdBIPS:      req.Header.ThresholdBIPS,
		Cosigners:          req.Header.Cosigners,
		CosignersThreshold: req.Header.CosignersThreshold,
		Timestamp:          timestamp,
	}

	encHeader, err := EncodeFTDCResponseHeader(header)
	if err != nil {
		return common.Hash{}, nil, nil, err
	}

	headerHash := crypto.Keccak256Hash(encHeader)
	reqBodyHash := crypto.Keccak256Hash(req.RequestBody)
	resBodyHash := crypto.Keccak256Hash(responseBody)

	msgHash := crypto.Keccak256Hash(headerHash[:], reqBodyHash[:], resBodyHash[:])

	buffer := bytes.NewBuffer(nil)
	buffer.WriteByte(1)           // 1 byte (protocolId=1)
	buffer.Write(make([]byte, 5)) // 4 bytes (votingRoundId=0), 1 byte (isSecureRandom=false)
	buffer.Write(msgHash[:])      // 32 bytes
	msgHashPrepended := buffer.Bytes()

	hashToBeSigned := crypto.Keccak256Hash(msgHashPrepended)

	return hashToBeSigned, msgHashPrepended, encHeader, nil
}
