package ftdcutils

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
)

func ValidateProve(insData *instruction.DataFixed, variableMessages []hexutil.Bytes, signers []common.Address, isSignerDataProvider []bool) ([]byte, error) {
	ftdcReq, err := types.DecodeFTDCRequest(insData.OriginalMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to decode FTDC prove request: %w", err)
	}

	isSignerCosigner, err := utils.CheckCosigners(signers, isSignerDataProvider, ftdcReq.Header.Cosigners, ftdcReq.Header.CosignersThreshold)
	if err != nil {
		return nil, err
	}

	msgHash, encResHeader, err := types.HashFTDCMessage(ftdcReq, insData.AdditionalFixedMessage, insData.Timestamp)
	if err != nil {
		return nil, err
	}

	dpSigs, cosignerSigs, err := checkResponseSignatures(
		msgHash, variableMessages, signers, isSignerDataProvider, isSignerCosigner,
	)
	if err != nil {
		return nil, err
	}

	teeSignature, err := node.Sign(msgHash[:])
	if err != nil {
		return nil, err
	}

	result := types.FTDCProveResponse{
		ResponseHeader:         encResHeader,
		RequestBody:            ftdcReq.RequestBody,
		ResponseBody:           insData.AdditionalFixedMessage,
		TEESignature:           teeSignature,
		DataProviderSignatures: dpSigs,
		CosignerSignatures:     cosignerSigs,
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}

	return resultBytes, nil
}

func checkResponseSignatures(
	msgHash common.Hash,
	sigs []hexutil.Bytes,
	signers []common.Address,
	isSignerDP,
	isSignerCos []bool,
) ([]hexutil.Bytes, []hexutil.Bytes, error) {
	if err := validateSignatureInputs(sigs, signers, isSignerDP, isSignerCos); err != nil {
		return nil, nil, err
	}

	dpSigs := make([]hexutil.Bytes, 0)
	cosSigs := make([]hexutil.Bytes, 0)
	for i, signature := range sigs {
		err := utils.VerifySignature(msgHash[:], signature, signers[i])
		if err != nil {
			return nil, nil, err
		}
		if isSignerDP[i] {
			dpSigs = append(dpSigs, signature)
		}
		if isSignerCos[i] {
			cosSigs = append(cosSigs, signature)
		}
	}

	return dpSigs, cosSigs, nil
}

// validateSignatureInputs ensures all input slices have consistent lengths
func validateSignatureInputs(sigs []hexutil.Bytes, signers []common.Address, isSignerDP, isSignerCos []bool) error {
	sigCount := len(sigs)

	if sigCount != len(signers) {
		return errors.New("signature count does not match signer count")
	}

	if sigCount != len(isSignerDP) || sigCount != len(isSignerCos) {
		return errors.New("signature count does not match signer info length")
	}

	return nil
}
