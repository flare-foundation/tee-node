package ftdcutils

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flare-foundation/go-flare-common/pkg/contracts/relay"
	"github.com/flare-foundation/go-flare-common/pkg/encoding"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
)

var relayFunctionSelector []byte

func init() {
	relayABI, err := relay.RelayMetaData.GetAbi()
	if err != nil {
		panic(err)
	}

	relayFunctionSelector = relayABI.Methods["relay"].ID
}

func ValidateProve(insData *instruction.DataFixed,
	variableMessages []hexutil.Bytes,
	signers []common.Address,
	dataProviderIndex map[common.Address]int,
	signingPolicyBytes []byte,
) ([]byte, error) {
	ftdcReq, err := types.DecodeFTDCRequest(insData.OriginalMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to decode FTDC prove request: %w", err)
	}

	isSignerCosigner, err := utils.CheckCosigners(signers, dataProviderIndex, ftdcReq.Header.Cosigners, ftdcReq.Header.CosignersThreshold)
	if err != nil {
		return nil, err
	}

	hashToBeSigned, msgPrepended, encResHeader, err := types.HashFTDCMessage(ftdcReq, insData.AdditionalFixedMessage, insData.Timestamp)
	if err != nil {
		return nil, err
	}

	dpSigs, cosignerSigs, err := checkResponseSignatures(
		hashToBeSigned, variableMessages, signers, dataProviderIndex, isSignerCosigner,
	)
	if err != nil {
		return nil, err
	}
	dpSigsEncoded, err := prepareFinalizationTxInput(signingPolicyBytes, msgPrepended, dpSigs)
	if err != nil {
		return nil, err
	}

	teeSignature, err := node.Sign(hashToBeSigned[:])
	if err != nil {
		return nil, err
	}

	result := types.FTDCProveResponse{
		ResponseHeader:         encResHeader,
		RequestBody:            ftdcReq.RequestBody,
		ResponseBody:           insData.AdditionalFixedMessage,
		TEESignature:           teeSignature,
		DataProviderSignatures: dpSigsEncoded,
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
	dataProviderIndex map[common.Address]int,
	isSignerCos []bool,
) ([]encoding.IndexedSignature, []hexutil.Bytes, error) {
	if err := validateSignatureInputs(sigs, signers, isSignerCos); err != nil {
		return nil, nil, err
	}

	dpSigs := make([]encoding.IndexedSignature, 0)
	cosSigs := make([]hexutil.Bytes, 0)
	for i, signature := range sigs {
		err := utils.VerifySignature(msgHash[:], signature, signers[i])
		if err != nil {
			return nil, nil, err
		}
		if index, isSignerDP := dataProviderIndex[signers[i]]; isSignerDP {
			dpSigs = append(dpSigs, encoding.IndexedSignature{Index: index, Signature: signature})
		}
		if isSignerCos[i] {
			cosSigs = append(cosSigs, signature)
		}
	}
	slices.SortFunc(
		dpSigs,
		func(x, y encoding.IndexedSignature) int {
			if x.Index < y.Index {
				return -1
			}
			if x.Index > y.Index {
				return 1
			}
			return 0
		},
	)

	return dpSigs, cosSigs, nil
}

// validateSignatureInputs ensures all input slices have consistent lengths
func validateSignatureInputs(sigs []hexutil.Bytes, signers []common.Address, isSignerCos []bool) error {
	sigCount := len(sigs)

	if sigCount != len(signers) {
		return errors.New("signature count does not match signer count")
	}

	if sigCount != len(isSignerCos) {
		return errors.New("signature count does not match signer info length")
	}

	return nil
}

func prepareFinalizationTxInput(signingPolicyBytes []byte, msg []byte, sigs []encoding.IndexedSignature) ([]byte, error) {
	buffer := bytes.NewBuffer(nil)
	buffer.Write(relayFunctionSelector)
	buffer.Write(signingPolicyBytes)
	buffer.Write(msg[:])

	encodedSignatures, err := encoding.EncodeSignatures(sigs)
	if err != nil {
		return nil, err
	}

	buffer.Write(encodedSignatures)

	return buffer.Bytes(), nil
}
