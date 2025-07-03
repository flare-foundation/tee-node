package getutils

import (
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/tee-node/internal/attestation"
	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/policy"
	"github.com/flare-foundation/tee-node/internal/settings"
	pkgattestation "github.com/flare-foundation/tee-node/pkg/attestation"
	"github.com/flare-foundation/tee-node/pkg/types"
)

func GetTeeInfo(getAction *types.DirectInstructionData) ([]byte, error) {
	var teeInfoRequest types.TeeInfoRequest
	err := json.Unmarshal(getAction.Message, &teeInfoRequest)
	if err != nil {
		return nil, err
	}

	nodeInfo := node.GetNodeInfo()

	policy.Storage.RLock()
	activePolicy, _ := policy.Storage.GetActiveSigningPolicy()
	policy.Storage.RUnlock()

	var activePolicyHash common.Hash
	var activeSigningPolicyId uint32
	if activePolicy != nil {
		activePolicyHash, err = activePolicy.Hash()
		if err != nil {
			return nil, err
		}
		activeSigningPolicyId = activePolicy.RewardEpochId
	} else {
		activePolicyHash = settings.InitialPolicyHash
		activeSigningPolicyId = settings.InitialPolicyId
	}

	teeInfo := types.TeeInfo{
		Challenge:                teeInfoRequest.Challenge,
		PublicKey:                nodeInfo.PublicKey,
		Status:                   nodeInfo.Status,
		InitialSigningPolicyId:   settings.InitialPolicyId,
		InitialSigningPolicyHash: settings.InitialPolicyHash,
		LastSigningPolicyId:      activeSigningPolicyId,
		LastSigningPolicyHash:    activePolicyHash,
		Nonce:                    nodeInfo.Nonce,
		PauseNonce:               nodeInfo.PausingNonce,
		TeeTimestamp:             time.Now().Unix(),
	}
	teeInfoHash, err := teeInfo.Hash()
	if err != nil {
		return nil, err
	}

	attestationBytes, err := attestation.GetGoogleAttestationToken([]string{hex.EncodeToString(teeInfoHash[:])}, pkgattestation.PKITokenType)
	if err != nil {
		return nil, err
	}

	teeInfoResponse := types.TeeInfoResponse{
		TeeInfo:     teeInfo,
		Attestation: attestationBytes,
	}

	resultEncoded, err := json.Marshal(teeInfoResponse)
	if err != nil {
		return nil, err
	}

	return resultEncoded, nil
}
