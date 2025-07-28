package regutils

import (
	"encoding/json"
	"errors"

	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/verification"
	"github.com/flare-foundation/tee-node/internal/attestation"
	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/policy"
	"github.com/flare-foundation/tee-node/pkg/types"
)

func TeeAttestation(instructionData *instruction.DataFixed) ([]byte, error) {
	challenge, err := ValidateTeeAttestation(instructionData.OriginalMessage)
	if err != nil {
		return nil, err
	}

	nodeInfo := node.GetNodeInfo()

	policy.Storage.RLock()
	initialID, initialHash, activeID, activeHash := policy.SigningPolicyInfo()
	policy.Storage.RUnlock()

	teeInfoResponse, err := attestation.ConstructTeeInfoResponse(challenge, &nodeInfo, initialID, initialHash, activeID, activeHash)
	if err != nil {
		return nil, err
	}

	resultEncoded, err := json.Marshal(teeInfoResponse)
	if err != nil {
		return nil, err
	}

	return resultEncoded, nil
}

func ValidateTeeAttestation(attReq []byte) ([32]byte, error) {
	teeAttestationRequest, err := types.DecodeTeeAttestationRequest(attReq)
	if err != nil {
		return [32]byte{}, err
	}

	nodeInfo := node.GetNodeInfo()

	challenge, err := checkTeeAttestation(teeAttestationRequest, nodeInfo)
	if err != nil {
		return [32]byte{}, err
	}

	return challenge, nil
}

func checkTeeAttestation(teeAttestationRequest verification.ITeeVerificationTeeAttestation, nodeInfo node.NodeInfo) ([32]byte, error) {
	if teeAttestationRequest.TeeMachine.TeeId != nodeInfo.TeeId {
		return [32]byte{}, errors.New("TeeIds do not match")
	}
	if teeAttestationRequest.Challenge == [32]byte{} {
		return [32]byte{}, errors.New("challenge not given")
	}
	return teeAttestationRequest.Challenge, nil
}
