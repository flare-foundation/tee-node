package regutils

import (
	"encoding/json"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	cpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"

	"github.com/flare-foundation/tee-node/internal/attestation"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/types"
)

type Processor struct {
	node.InformerAndSigner
	pStorage *policy.Storage
}

// NewProcessor returns a registration utility processor bound to the provided
// node informerAndSigner and policy storage.
func NewProcessor(infoAndSig node.InformerAndSigner, pStorage *policy.Storage) Processor {
	return Processor{
		InformerAndSigner: infoAndSig,
		pStorage:          pStorage,
	}
}

// TEEAttestation handles the registration attestation instruction, producing a
// TEE info response when the threshold is reached and acknowledging other
// submission stages.
func (p *Processor) TEEAttestation(
	submissionTag types.SubmissionTag,
	dataFixed *instruction.DataFixed,
	_ []hexutil.Bytes,
	_ []common.Address,
	_ *cpolicy.SigningPolicy,
) ([]byte, []byte, error) {
	challenge, err := ValidateTeeAttestationRequest(dataFixed.OriginalMessage, p.Info().TeeID)
	if err != nil {
		return nil, nil, err
	}

	switch submissionTag {
	case types.End:
		return nil, nil, nil
	case types.Threshold:
		nodeInfo := p.Info()
		p.pStorage.RLock()
		initialID, initialHash, activeID, activeHash := p.pStorage.Info()
		p.pStorage.RUnlock()

		teeInfoResponse, err := attestation.ConstructTEEInfoResponse(challenge, &nodeInfo, initialID, initialHash, activeID, activeHash)
		if err != nil {
			return nil, nil, err
		}

		mdHash, err := teeInfoResponse.MachineData.Hash()
		if err != nil {
			return nil, nil, err
		}

		mdSignature, err := p.Sign(mdHash[:])
		if err != nil {
			return nil, nil, err
		}
		teeInfoResponse.DataSignature = mdSignature

		resultEncoded, err := json.Marshal(teeInfoResponse)
		if err != nil {
			return nil, nil, err
		}

		return resultEncoded, nil, nil
	default:
		return nil, nil, errors.New("unexpected submission tag")
	}
}
