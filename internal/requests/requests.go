package requests

import (
	"crypto/ecdsa"
	"tee-node/internal/config"
	"tee-node/internal/node"
	"tee-node/internal/policy"
	"tee-node/internal/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func Sign(r *instruction.Data, privKey *ecdsa.PrivateKey) ([]byte, error) {
	hash, err := r.HashForSigning()
	if err != nil {
		return nil, err
	}
	signature, err := utils.Sign(hash[:], privKey)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func CheckSignature(r *instruction.Data, signature []byte, requestPolicy *policy.SigningPolicy) (common.Address, error) {
	hash, err := r.HashForSigning()
	if err != nil {
		return common.Address{}, err
	}

	return utils.CheckSignature(hash[:], signature, requestPolicy.Voters)
}

func CheckSigner(request *instruction.Data, signature []byte) (common.Address, error) {
	requestPolicy := policy.GetSigningPolicy(uint32(request.RewardEpochID.Uint64()))
	if requestPolicy == nil {
		return common.Address{}, nil
	}

	providerAddress, err := CheckSignature(request, signature, requestPolicy)
	if err != nil {
		return common.Address{}, err
	}

	return providerAddress, nil
}

func CheckRequest(instructionData *instruction.Data) error {
	nodeId := node.GetNodeId()
	if instructionData.TeeID.Hex() != nodeId.Id {
		return errors.New("invalid TEE id")
	}

	if policy.ActiveSigningPolicy.RewardEpochId < uint32(instructionData.RewardEpochID.Uint64()) {
		return errors.New("reward epoch not started yet")
	}
	if policy.ActiveSigningPolicy.RewardEpochId-uint32(instructionData.RewardEpochID.Uint64()) > config.ACTIVE_POLICY_COUNT {
		return errors.New("reward epoch id too old")
	}

	// Check the command is valid
	valid := isValidCommand(utils.OpHashToString(instructionData.OPType), utils.OpHashToString(instructionData.OPCommand))
	if !valid {
		return status.Error(codes.InvalidArgument, "invalid command for operation type")
	}

	return nil
}

// IsValidSubCommand checks if the OpType and Command is valid for a given operation type
func isValidCommand(op, command string) bool {
	validCommands, exists := config.InstructionOperations[op]
	if !exists {
		return false
	}

	for _, cmd := range validCommands {
		if cmd == command {
			return true
		}
	}
	return false
}
