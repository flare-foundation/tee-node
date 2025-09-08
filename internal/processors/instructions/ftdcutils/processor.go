package ftdcutils

import (
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/tee-node/pkg/ftdc"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/types"
)

type Processor struct {
	node.Signer
}

func NewProcessor(sig node.Signer) Processor {
	return Processor{Signer: sig}
}

func (p *Processor) Prove(
	_ types.SubmissionTag,
	dataFixed *instruction.DataFixed,
	variableMessages []hexutil.Bytes,
	signers []common.Address,
	signingPolicy *policy.SigningPolicy,
) ([]byte, []byte, error) {
	req, err := ftdc.DecodeRequest(dataFixed.OriginalMessage)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode FTDC prove request: %w", err)
	}

	hashToBeSigned, msgPrepended, encResHeader, err := ftdc.HashMessage(req, dataFixed.AdditionalFixedMessage, dataFixed.Cosigners, dataFixed.CosignersThreshold, dataFixed.Timestamp)
	if err != nil {
		return nil, nil, err
	}

	dpSigs, cosignerSigs, err := checkResponseSignatures(
		hashToBeSigned, variableMessages, signers, signingPolicy.Voters, dataFixed.Cosigners,
	)
	if err != nil {
		return nil, nil, err
	}

	dpSigsEncoded, err := prepareFinalizationTxInput(signingPolicy.RawBytes(), msgPrepended, dpSigs)
	if err != nil {
		return nil, nil, err
	}

	teeSignature, err := p.Sign(hashToBeSigned[:])
	if err != nil {
		return nil, nil, err
	}

	result := ftdc.ProveResponse{
		ResponseHeader:         encResHeader,
		RequestBody:            req.RequestBody,
		ResponseBody:           dataFixed.AdditionalFixedMessage,
		TEESignature:           teeSignature,
		DataProviderSignatures: dpSigsEncoded,
		CosignerSignatures:     cosignerSigs,
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return nil, nil, err
	}

	return resultBytes, nil, nil
}
