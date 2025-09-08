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
	node.Informer
	pStorage *policy.Storage
}

func NewProcessor(informer node.Informer, pStorage *policy.Storage) Processor {
	return Processor{
		Informer: informer,
		pStorage: pStorage,
	}
}

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

		resultEncoded, err := json.Marshal(teeInfoResponse)
		if err != nil {
			return nil, nil, err
		}

		return resultEncoded, nil, nil
	default:
		return nil, nil, errors.New("unexpected submission tag")
	}
}
