package instructionservice

import (
	api "tee-node/api/types"
	"tee-node/pkg/attestation"
	"tee-node/pkg/requests"
	"tee-node/pkg/utils"

	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Call forwards the call to the appropriate service and method
func SendSignedInstruction(instructionMessage *instruction.Instruction) (*api.InstructionResponse, error) {
	// TODO: Is there any other check that should be done here?
	// Todo: Checks if InstructionId is valid, rewardEpochId is correct, etc.
	// TODO: Anti DOS checks
	err := requests.CheckRequest(&instructionMessage.Data)
	if err != nil {
		return nil, err
	}

	signer, err := requests.CheckSigner(&instructionMessage.Data, instructionMessage.Signature)
	if err != nil {
		return nil, err
	}
	requestCounter, err := requests.GetRequestCounter(&instructionMessage.Data)
	if err != nil {
		return nil, err
	}

	requestCounter.Lock()
	defer requestCounter.Unlock()
	requestCounter.AddRequestSignature(signer, instructionMessage.Signature)
	requestCounter.AddRequestVariableMessage(signer, instructionMessage.Data.AdditionalVariableMessage)

	// todo: currently the threshold if equal for all, should be changed
	thresholdReached := requestCounter.ThresholdReached()
	requests.ProcessInstructionIdMapping(requestCounter.Request)

	finalize := thresholdReached && !requestCounter.Done
	if finalize {
		switch utils.OpHashToString(instructionMessage.Data.OPType) {
		case "REG":
			requestCounter.Result, err = handleRegPostRequest(requestCounter)

		case "POLICY":
			requestCounter.Result, err = handlePolicyPostRequest(requestCounter)

		case "WALLET":
			requestCounter.Result, err = handleWalletPostRequest(requestCounter)

		case "XRP":
			requestCounter.Result, err = handleXrpPostRequest(requestCounter)

		case "BTC":
			requestCounter.Result, err = handleBtcPostRequest(requestCounter)

		case "FDC":
			requestCounter.Result, err = handleFdcPostRequest(requestCounter)

		default:
			return nil, status.Error(codes.InvalidArgument, "invalid operation type")
		}
		if err != nil {
			return nil, err
		}

		requestCounter.Done = true
	}

	// TODO: Again what do we put in the nonces beside the challenge?
	token, err := attestation.CreateAttestation([]string{instructionMessage.Challenge.String()}, attestation.OIDCTokenType) // todo: add response to the attested value?
	if err != nil {
		return nil, err
	}

	var status string // todo: maybe some other statuses
	if requestCounter.Done {
		status = "done"
	} else {
		status = "processing"
	}

	return &api.InstructionResponse{
		ResponseBase: api.ResponseBase{
			Status: status,
			Token:  token,
		},
		Data:      []byte{}, // todo: do we need this?
		Finalized: finalize,
	}, nil

}

func InstructionResult(instructionQuery *api.InstructionResultRequest) (*api.InstructionResultResponse, error) {
	requestsWithId, ok := requests.GetHashesWithId(instructionQuery.InstructionId)
	if !ok {
		return nil, status.Error(codes.NotFound, "request not found")
	}

	// find the request that was finalized
	var requestCounterFinalized *requests.RequestCounter
	for _, instructionHash := range requestsWithId {
		requestCounter, exists, err := requests.GetRequestCounterByHash(instructionHash)
		// these two errors should not happen
		if err != nil {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		if !exists {
			return nil, errors.New("request non existent")
		}
		if !requestCounter.Done || requestCounter.Result == nil {
			continue
		} else {
			requestCounterFinalized = requestCounter
			break
		}
	}
	if requestCounterFinalized == nil {
		return nil, status.Error(codes.NotFound, "request not finalized")
	}

	var instructionResultData []byte
	var err error

	switch utils.OpHashToString(requestCounterFinalized.Request.OPType) {
	case "REG":
		instructionResultData, err = handleRegGetRequest(requestCounterFinalized)

	case "WALLET":
		instructionResultData, err = handleWalletGetRequest(requestCounterFinalized)

	case "XRP":
		instructionResultData, err = handleXrpGetRequest(requestCounterFinalized)

	case "BTC":
		instructionResultData, err = handleBtcGetRequest(requestCounterFinalized)

	case "FDC":
		instructionResultData, err = handleFdcGetRequest(requestCounterFinalized)

	default:
		return nil, status.Error(codes.InvalidArgument, "invalid operation type")
	}
	if err != nil {
		return nil, err
	}

	token, err := attestation.CreateAttestation([]string{instructionQuery.Challenge}, attestation.OIDCTokenType) // todo: add response to the attested value?
	if err != nil {
		return nil, err
	}

	return &api.InstructionResultResponse{
		ResponseBase: api.ResponseBase{
			Status: "OK",
			Token:  token,
		},
		Data: instructionResultData,
	}, nil
}

func InstructionStatus(instructionQuery *api.InstructionResultRequest) (*api.InstructionStatusResponse, error) {
	// find the request that was finalized
	requestsWithId, ok := requests.GetHashesWithId(instructionQuery.InstructionId)
	if !ok {
		return nil, errors.New("request not found")
	}

	// var requestCounterFinalized *requests.RequestCounter[api.InstructionData]
	var voteResults []api.VoteResult = make([]api.VoteResult, 0)
	instructionStatus := "inProgress"
	for _, instructionHash := range requestsWithId {
		requestCounter, exists, err := requests.GetRequestCounterByHash(instructionHash)
		if err != nil {
			return nil, status.Error(codes.NotFound, err.Error()) // TODO: is an error to strict here?
		}
		if !exists {
			return nil, errors.New("request non existent")
		}

		voteResults = append(voteResults, api.VoteResult{
			NumberOfVotes: uint16(len(requestCounter.RequestSignatures)),
			TotalWeight:   requestCounter.CurrentWeight(),
		})

		if requestCounter.Done {
			instructionStatus = "success"
		}
	}

	// TODO: Again what do we put in the nonces beside the challenge?
	token, err := attestation.CreateAttestation([]string{instructionQuery.Challenge}, attestation.OIDCTokenType) // todo: add response to the attested value?
	if err != nil {
		return nil, err
	}

	return &api.InstructionStatusResponse{
		ResponseBase: api.ResponseBase{
			Status: "OK",
			Token:  token,
		},
		Data: api.InstructionStatusData{
			VoteResults: voteResults,
			Status:      instructionStatus,
			ErrorLog:    "", // TODO: add error log
		},
	}, nil
}
