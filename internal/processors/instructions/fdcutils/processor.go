package fdcutils

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/pkg/fdc"
	"github.com/flare-foundation/tee-node/pkg/types"
)

type Processor struct {
	node.InformerAndSigner
}

// NewProcessor creates an FDC proof processor backed by the provided node, which
// supplies both the signing key and the chain ID bound into the proof.
func NewProcessor(infoAndSig node.InformerAndSigner) Processor {
	return Processor{InformerAndSigner: infoAndSig}
}

// Prove verifies the FDC request, aggregates the data provider and cosigner
// signatures, and returns the encoded proof payload signed by the TEE.
func (p *Processor) Prove(
	_ context.Context,
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

	messageHash, encResHeader, err := fdc.HashMessage(p.Info().ChainID, req, dataFixed.AdditionalFixedMessage, dataFixed.Cosigners, dataFixed.CosignersThreshold, dataFixed.Timestamp)
	if err != nil {
		return nil, nil, err
	}

	// Data-provider (signing-policy) signatures and cosigner signatures both
	// recover against the prefixed hash. The TEE's own signature uses messageHash directly.
	relayPrefixedHash := fdc.RelayPrefixedHash(messageHash)
	dpSigs, cosignerSigs, err := checkResponseSignatures(
		relayPrefixedHash, variableMessages, signers, signingPolicy.Voters, dataFixed.Cosigners,
	)
	if err != nil {
		return nil, nil, err
	}

	dpSigsEncoded, err := prepareFinalizationTxInput(signingPolicy.RawBytes(), messageHash.Bytes(), dpSigs)
	if err != nil {
		return nil, nil, err
	}

	teeSignature, err := p.Sign(messageHash.Bytes())
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
