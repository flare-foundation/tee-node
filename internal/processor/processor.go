package processor

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/processor/direct"
	"github.com/flare-foundation/tee-node/internal/processor/instructions"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/pkg/errors"
)

func RunTeeProcessor(proxyUrl string) {
	go runQueueProcessing(proxyUrl, "main")
	runQueueProcessing(proxyUrl, "read")
}

func runQueueProcessing(proxyUrl string, queueId string) {
	// V2: everything is ready for processing actions in parallel, should we?
	for {
		var action *types.Action
		var response *types.ActionResponse

		action, err := getAction(fmt.Sprintf("%s/queue/%s", proxyUrl, queueId))
		if err != nil {
			logger.Errorf("error getting action: %v", err)
			goto sleep
		}
		if action == nil || action.Data.ID == [32]byte{} {
			goto sleep
		}

		checkAndAdapt(action)

		response, err = processAction(action)
		if err != nil {
			logger.Errorf("error processing action: %v", err)
			response = &types.ActionResponse{
				Result: types.ActionResult{
					ID:            action.Data.ID,
					SubmissionTag: action.Data.SubmissionTag,
					Status:        false,
					Version:       settings.EncodingVersion,
					Log:           err.Error(),
				},
			}
		}

		err = postActionResponse(proxyUrl+"/result", response)
		if err != nil {
			logger.Errorf("error posting result: %v", err)
		}

	sleep:
		time.Sleep(settings.QueuedActionsSleepTime)
	}
}

func checkAndAdapt(action *types.Action) {
	if len(action.AdditionalVariableMessages) == 0 {
		action.AdditionalVariableMessages = make([]hexutil.Bytes, len(action.Signatures))
	}
	// todo: additional checks?
}

func processAction(action *types.Action) (*types.ActionResponse, error) {
	var err error
	result := &types.ActionResult{
		ID:            action.Data.ID,
		SubmissionTag: action.Data.SubmissionTag,
		Status:        true,
		Version:       settings.EncodingVersion,
	}

	switch action.Data.Type {
	case types.Instruction:
		instructionData, err := parse[instruction.DataFixed](action.Data.Message)
		if err != nil {
			return nil, err
		}

		message, resultStatus, err := instructions.ProcessInstruction(
			instructionData,
			action.AdditionalVariableMessages,
			action.Signatures,
			action.Data.SubmissionTag,
			action.Timestamps,
		)
		fmt.Println("instructions", utils.OpHashToString(instructionData.OpType), utils.OpHashToString(instructionData.OpCommand), instructionData.TeeId, instructionData.RewardEpochId, err)

		result.AdditionalResultStatus = resultStatus
		if err != nil {
			return nil, err
		}

		result.OPCommand = instructionData.OpCommand
		result.OPType = instructionData.OpType
		result.Data = message

	case types.Direct:
		directInstruction, err := parse[types.DirectInstruction](action.Data.Message)
		if err != nil {
			return nil, err
		}

		message, err := direct.ProcessDirectInstruction(directInstruction)
		fmt.Println("instructions", utils.OpHashToString(directInstruction.OPType), utils.OpHashToString(directInstruction.OPCommand), err)
		if err != nil {
			return nil, err
		}

		result.OPCommand = directInstruction.OPCommand
		result.OPType = directInstruction.OPType
		result.Data = message

	default:
		err = errors.New("invalid queued action type")
		return nil, err
	}

	msgHash := crypto.Keccak256(result.Data)
	sig, err := node.Sign(msgHash)
	if err != nil {
		return nil, err
	}

	return &types.ActionResponse{
		Result:    *result,
		Signature: sig,
	}, nil
}

type ValidRequestType interface {
	instruction.DataFixed | types.DirectInstruction
}

func parse[T ValidRequestType](message []byte) (*T, error) {
	var maxBodySize int
	switch any(new(T)).(type) {
	case *instruction.DataFixed:
		maxBodySize = settings.MaxInstructionSize
	case *types.DirectInstruction:
		maxBodySize = settings.MaxActionSize
	default:
		return nil, errors.New("Invalid request type")
	}

	// Check if the request body size exceeds the limit
	if len(message) > maxBodySize {
		return nil, errors.New("request too large")
	}

	var req T
	err := json.Unmarshal(message, &req)
	if err != nil {
		return nil, errors.Errorf("invalid JSON, %v", err)
	}

	return &req, nil
}
