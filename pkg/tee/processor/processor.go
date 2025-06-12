package processor

import (
	"encoding/json"
	"tee-node/api/types"
	"tee-node/pkg/tee/node"
	"tee-node/pkg/tee/processor/actions"
	"tee-node/pkg/tee/processor/instructions"
	"tee-node/pkg/tee/settings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/pkg/errors"
)

var emptyQueuedActionInfo = types.QueuedActionInfo{}

func RunTeeProcessor(proxyUrl string) {
	go runQueueProcessing(proxyUrl, "main")
	runQueueProcessing(proxyUrl, "read")
}

func runQueueProcessing(proxyUrl string, queueId string) {
	for {
		var action *types.QueuedAction
		var result *types.QueueActionResult
		var response *types.QueueActionResponse

		actionInfo, err := getActionInfo(proxyUrl + "/queue/" + queueId)
		if err != nil {
			logger.Errorf("error getting action info: %v", err)
			goto sleep
		}
		if *actionInfo == emptyQueuedActionInfo {
			goto sleep
		}

		action, err = getAction(proxyUrl+"/dequeue", actionInfo)
		if err != nil {
			logger.Errorf("error getting action: %v", err)
			goto sleep
		}

		result, err = processQueuedAction(action)
		if err != nil {
			logger.Errorf("error processing action: %v", err)
		}

		response = &types.QueueActionResponse{
			ActionId:      actionInfo.ActionId,
			SubmissionTag: actionInfo.SubmissionTag,
			Result:        *result,
		}
		err = postActionResponse(proxyUrl+"/result", response)
		if err != nil {
			logger.Errorf("error posting result: %v", err)
		}

	sleep:
		time.Sleep(settings.QueuedActionsSleepTime)
	}
}

func processQueuedAction(action *types.QueuedAction) (*types.QueueActionResult, error) {
	var err error
	response := &types.QueueActionResult{}

	switch action.Data.Type {
	case types.InstructionType:
		instructionData, err := parse[instruction.DataFixed](action.Data.Message)
		if err != nil {
			response.Log = err.Error()
			return response, err
		}

		message, err := instructions.ProcessInstruction(
			instructionData,
			action.AdditionalVariableMessages,
			action.Signatures,
			action.CosignerAdditionalVariableMessages,
			action.CosignerSignatures,
		)
		if err != nil {
			response.Log = err.Error()
			return response, err
		}

		response.Status = true
		response.OPCommand = instructionData.OPCommand
		response.OPType = instructionData.OPType
		response.ResultData = types.QueueActionResultData{Message: message}

	case types.ActionType:
		getData, err := parse[types.ActionData](action.Data.Message)
		if err != nil {
			response.Log = err.Error()
			return response, err
		}

		message, err := actions.ProcessAction(getData)
		if err != nil {
			response.Log = err.Error()
			return response, err
		}

		response.Status = true
		response.OPCommand = getData.OPCommand
		response.OPType = getData.OPType
		response.ResultData = types.QueueActionResultData{Message: message}

	default:
		err = errors.New("invalid queued action type")
		response.Log = err.Error()
		return response, err
	}

	if len(response.ResultData.Message) != 0 {
		msgHash := crypto.Keccak256Hash(response.ResultData.Message)

		response.ResultData.Signature, err = node.Sign(msgHash[:])
		if err != nil {
			response.Log = err.Error()
			return response, err
		}
	}

	return response, nil
}

type ValidRequestType interface {
	instruction.DataFixed | types.ActionData
}

func parse[T ValidRequestType](message []byte) (*T, error) {
	var maxBodySize int
	switch any(new(T)).(type) {
	case *instruction.DataFixed:
		maxBodySize = settings.MaxInstructionSize
	case *types.ActionData:
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
