package fdcutils

import (
	"bytes"
	"errors"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flare-foundation/go-flare-common/pkg/contracts/relay"
	"github.com/flare-foundation/go-flare-common/pkg/encoding"
	"github.com/flare-foundation/go-flare-common/pkg/voters"
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

func checkResponseSignatures(
	msgHash common.Hash,
	sigs []hexutil.Bytes,
	signers []common.Address,
	dataProviders *voters.Set,
	cosigners []common.Address,
) ([]encoding.IndexedSignature, []hexutil.Bytes, error) {
	if err := validateSignatureInputs(sigs, signers); err != nil {
		return nil, nil, err
	}

	dpSigs := make([]encoding.IndexedSignature, 0, len(sigs))
	cosSigs := make([]hexutil.Bytes, 0, min(len(sigs), len(cosigners)))
	for i, signature := range sigs {
		err := utils.VerifySignature(msgHash[:], signature, signers[i])
		if err != nil {
			return nil, nil, err
		}
		if dpIndex := dataProviders.VoterIndex(signers[i]); dpIndex != -1 {
			dpSigs = append(dpSigs, encoding.IndexedSignature{Index: dpIndex, Signature: signature})
		}
		if slices.Contains(cosigners, signers[i]) {
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
func validateSignatureInputs(sigs []hexutil.Bytes, signers []common.Address) error {
	sigCount := len(sigs)
	if sigCount != len(signers) {
		return errors.New("signature count does not match signer count")
	}

	return nil
}

func prepareFinalizationTxInput(signingPolicyBytes []byte, msg []byte, sigs []encoding.IndexedSignature) ([]byte, error) {
	buffer := bytes.NewBuffer(nil)
	buffer.Write(relayFunctionSelector)
	buffer.Write(signingPolicyBytes)
	buffer.Write(msg)

	encodedSignatures, err := encoding.EncodeSignatures(sigs)
	if err != nil {
		return nil, err
	}

	buffer.Write(encodedSignatures)

	return buffer.Bytes(), nil
}
