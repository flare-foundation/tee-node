package getutils

import (
	"encoding/json"

	"github.com/flare-foundation/tee-node/internal/attestation"
	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/policy"
	"github.com/flare-foundation/tee-node/pkg/types"
)

func GetTeeInfo(getAction *types.DirectInstruction) ([]byte, error) {
	var teeInfoRequest types.TeeInfoRequest
	err := json.Unmarshal(getAction.Message, &teeInfoRequest)
	if err != nil {
		return nil, err
	}

	nodeInfo := node.GetNodeInfo()

	policy.Storage.RLock()
	initialID, initialHash, activeID, activeHash := policy.SigningPolicyInfo()
	policy.Storage.RUnlock()

	teeInfoResponse, err := attestation.ConstructTeeInfoResponse(teeInfoRequest.Challenge, &nodeInfo, initialID, initialHash, activeID, activeHash)
	if err != nil {
		return nil, err
	}

	resultEncoded, err := json.Marshal(teeInfoResponse)
	if err != nil {
		return nil, err
	}

	return resultEncoded, nil
}
