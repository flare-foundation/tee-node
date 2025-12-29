package attestation

import (
	"encoding/hex"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/attestation/googlecloud"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/attestation"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/types"
)

// ConstructTEEInfoResponse creates a tee info attestation response for the given challenge
func ConstructTEEInfoResponse(challenge common.Hash, nodeInfo *node.Info, initialID uint32, initialHash common.Hash, activeID uint32, activeHash common.Hash) (*types.TeeInfoResponse, error) {
	state, err := nodeInfo.State.State()
	if err != nil {
		return nil, err
	}

	teeInfo := types.TeeInfo{
		Challenge:                challenge,
		PublicKey:                nodeInfo.PublicKey,
		InitialSigningPolicyID:   initialID,
		InitialSigningPolicyHash: initialHash,
		LastSigningPolicyID:      activeID,
		LastSigningPolicyHash:    activeHash,
		State:                    state,
		TeeTimestamp:             uint64(time.Now().Unix()),
	}

	h, err := teeInfo.Hash()
	if err != nil {
		return nil, err
	}

	attestationBytes, err := GetGoogleAttestationToken([]string{hex.EncodeToString(h)}, attestation.PKITokenType)
	if err != nil {
		return nil, err
	}

	cHash := settings.TestCodeHash
	platform := settings.TestPlatform

	if settings.Mode == 0 {
		claims := &attestation.NeededClaims{}
		_, claims, err := googlecloud.ParsePKITokenUnverifiedClaims(string(attestationBytes), claims)
		if err != nil {
			return nil, err
		}

		cHash, err = claims.CodeHash()
		if err != nil {
			return nil, err
		}

		platform, err = claims.Platform()
		if err != nil {
			return nil, err
		}
	}

	mData := types.MachineData{
		ExtensionID:  nodeInfo.ExtensionID,
		InitialOwner: nodeInfo.InitialOwner,
		CodeHash:     cHash,
		Platform:     platform,
		PublicKey:    nodeInfo.PublicKey,
	}

	teeInfoResponse := types.TeeInfoResponse{
		TeeInfo:     teeInfo,
		MachineData: mData,
		Attestation: attestationBytes,
	}

	return &teeInfoResponse, nil
}
