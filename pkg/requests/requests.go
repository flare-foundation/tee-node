package requests

import (
	"crypto/ecdsa"
	"tee-node/pkg/config"
	"tee-node/pkg/node"
	"tee-node/pkg/policy"
	"tee-node/pkg/utils"

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

func CheckRequest(instructionData *instruction.Data) (bool, error) {
	if instructionData == nil {
		return false, errors.New("instruction data is nil")
	}

	if instructionData.TeeID.Hex() != node.GetTeeId().Hex() {
		return false, errors.New("invalid TEE id")
	}

	activeSigningPolicy := policy.GetActiveSigningPolicy()

	isActivePolicy := activeSigningPolicy.RewardEpochId == uint32(instructionData.RewardEpochID.Uint64())
	isPreviousPolicy := activeSigningPolicy.RewardEpochId == uint32(instructionData.RewardEpochID.Uint64())+1
	if !isActivePolicy && !isPreviousPolicy {
		return false, errors.New("reward epoch id too old")
	}

	valid := isValidCommand(utils.OpHashToString(instructionData.OPType), utils.OpHashToString(instructionData.OPCommand))
	if !valid {
		return false, status.Error(codes.InvalidArgument, "invalid command for operation type")
	}

	return isActivePolicy, nil
}

// Check if the request is new
func IsProposer(requestHash string) bool {
	_, exists := GetRequestCounterByHash(requestHash)
	return !exists
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

// validateRequestSize checks the size of the request fields
func ValidateRequestSize(instruction *instruction.Instruction) error {
	// Check the size of the challenge and signature
	if len(instruction.Challenge) > config.MaxChallengeSize {
		return status.Error(codes.InvalidArgument, "challenge exceeds maximum size")
	}
	if len(instruction.Signature) > config.MaxSignatureSize {
		return status.Error(codes.InvalidArgument, "signature exceeds maximum size")
	}

	// Check the size of the instruction data fields
	instructionData := instruction.Data
	if len(instructionData.InstructionID.Bytes()) > config.MaxInstructionFieldSize {
		return status.Error(codes.InvalidArgument, "instructionId exceeds maximum size")
	}
	if len(instructionData.TeeID.Bytes()) > config.MaxInstructionFieldSize {
		return status.Error(codes.InvalidArgument, "teeId exceeds maximum size")
	}
	if len(instructionData.OPType.Bytes()) > config.MaxInstructionFieldSize {
		return status.Error(codes.InvalidArgument, "opType exceeds maximum size")
	}
	if len(instructionData.OPCommand.Bytes()) > config.MaxInstructionFieldSize {
		return status.Error(codes.InvalidArgument, "opCommand exceeds maximum size")
	}

	// Check the size of the different messages
	messageSizeConstraint := config.MaxRequestSize[utils.OpHashToString(instructionData.OPType)][utils.OpHashToString(instructionData.OPCommand)]
	if len(instructionData.OriginalMessage) > messageSizeConstraint.MaxOriginalMessageSize {
		return status.Error(codes.InvalidArgument, "originalMessage exceeds maximum size")
	}
	if len(instructionData.AdditionalFixedMessage) > messageSizeConstraint.MaxAdditionalFixedMessageSize {
		return status.Error(codes.InvalidArgument, "additionalFixedMessage exceeds maximum size")
	}
	if len(instructionData.AdditionalVariableMessage) > messageSizeConstraint.MaxAdditionalVariableMessageSize {
		return status.Error(codes.InvalidArgument, "additionalVariableMessage exceeds maximum size")
	}

	return nil
}
