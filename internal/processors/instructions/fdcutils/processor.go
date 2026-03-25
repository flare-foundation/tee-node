package fdcutils

import (
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/tee-node/pkg/fdc"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/types"
)

type Processor struct {
	node.Signer
}

// NewProcessor creates an FDC proof processor backed by the provided signer.
func NewProcessor(sig node.Signer) Processor {
	return Processor{Signer: sig}
}

// Prove verifies the FDC request, aggregates the data provider and cosigner
// signatures, and returns the encoded proof payload signed by the TEE.
func (p *Processor) Prove(
	_ types.SubmissionTag,
	dataFixed *instruction.DataFixed,
	variableMessages []hexutil.Bytes,
	signers []common.Address,
	signingPolicy *policy.SigningPolicy,
) ([]byte, []byte, error) {
	req, err := fdc.DecodeRequest(dataFixed.OriginalMessage)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode FDC prove request: %w", err)
	}

	hashToBeSigned, msgHash, msgPrepended, encResHeader, err := fdc.HashMessage(req, dataFixed.AdditionalFixedMessage, dataFixed.Cosigners, dataFixed.CosignersThreshold, dataFixed.Timestamp)
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

	teeSignature, err := p.Sign(msgHash.Bytes())
	if err != nil {
		return nil, nil, err
	}

	result := fdc.ProveResponse{
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
