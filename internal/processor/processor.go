package processor

import (
	"encoding/json"
	"time"

	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/processor/direct"
	"github.com/flare-foundation/tee-node/internal/processor/instructions"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/types"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/pkg/errors"
)

var emptyQueuedActionInfo = types.ActionInfo{}

func RunTeeProcessor(proxyUrl string) {
	go runQueueProcessing(proxyUrl, "main")
	runQueueProcessing(proxyUrl, "read")
}

func runQueueProcessing(proxyUrl string, queueId string) {
	for {
		var action *types.Action
		var result *types.Result
		var response *types.ActionResponse

		log := ""
		status := true

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

		checkAndAdapt(action)

		result, err = processAction(action)
		if err != nil {
			log = err.Error()
			status = false
			logger.Errorf("error processing action: %v", err)
		}

		response = &types.ActionResponse{
			ID:            actionInfo.ActionId,
			SubmissionTag: actionInfo.SubmissionTag,
			Status:        status,
			Log:           log,
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

func checkAndAdapt(action *types.Action) {
	if len(action.AdditionalVariableMessages) == 0 {
		action.AdditionalVariableMessages = make([]hexutil.Bytes, len(action.Signatures))
	}
	// todo: additional checks?
}

func processAction(action *types.Action) (*types.Result, error) {
	var err error
	response := &types.Result{}

	switch action.Data.Type {
	case types.Instruction:
		instructionData, err := parse[instruction.DataFixed](action.Data.Message)
		if err != nil {
			return response, err
		}

		message, resultStatus, err := instructions.ProcessInstruction(
			instructionData,
			action.AdditionalVariableMessages,
			action.Signatures,
			action.Data.SubmissionTag,
			action.Timestamps,
		)
		response.AdditionalResultStatus = resultStatus
		if err != nil {
			return response, err
		}

		response.OPCommand = instructionData.OPCommand
		response.OPType = instructionData.OPType
		response.ResultData = types.ActionResultData{Message: message}

	case types.Direct:
		getData, err := parse[types.DirectInstructionData](action.Data.Message)
		if err != nil {
			return response, err
		}

		message, err := direct.ProcessDirectInstruction(getData)
		if err != nil {
			return response, err
		}

		response.OPCommand = getData.OPCommand
		response.OPType = getData.OPType
		response.ResultData = types.ActionResultData{Message: message}

	default:
		err = errors.New("invalid queued action type")
		return response, err
	}

	if len(response.ResultData.Message) != 0 {
		msgHash := crypto.Keccak256Hash(response.ResultData.Message)

		response.ResultData.Signature, err = node.Sign(msgHash[:])
		if err != nil {
			return response, err
		}
	}

	return response, nil
}

type ValidRequestType interface {
	instruction.DataFixed | types.DirectInstructionData
}

func parse[T ValidRequestType](message []byte) (*T, error) {
	var maxBodySize int
	switch any(new(T)).(type) {
	case *instruction.DataFixed:
		maxBodySize = settings.MaxInstructionSize
	case *types.DirectInstructionData:
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
