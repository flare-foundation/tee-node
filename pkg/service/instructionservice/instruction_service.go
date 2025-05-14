package instructionservice

import (
	"encoding/hex"
	"strconv"
	api "tee-node/api/types"
	"tee-node/pkg/attestation"
	"tee-node/pkg/config"
	"tee-node/pkg/requests"
	"tee-node/pkg/service/actionservice/governanceactions"
	"tee-node/pkg/utils"

	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Call forwards the call to the appropriate service and method
func SendSignedInstruction(instructionMessage *instruction.Instruction) (*api.InstructionResponse, error) {
	// TODO: Is there any other check that should be done here?
	if governanceactions.IsTeePaused() {
		return nil, errors.New("TEE is paused")
	}

	inActivePolicy, err := requests.CheckRequest(&instructionMessage.Data)
	if err != nil {
		return nil, err
	}

	err = requests.ValidateRequestSize(instructionMessage)
	if err != nil {
		return nil, err
	}

	signer, err := requests.CheckSigner(&instructionMessage.Data, instructionMessage.Signature)
	if err != nil {
		return nil, err
	}

	// Check if the request is a new request proposal and if so, is the signer allowed to propose
	reqHashFixed, err := instructionMessage.Data.HashFixed()
	if err != nil {
		return nil, err
	}
	reqHash := hex.EncodeToString(reqHashFixed[:])
	isProposer := requests.IsProposer(reqHash)

	var requestCounter *requests.RequestCounter
	if isProposer {
		err := requests.CanProposeNewRequest(signer, inActivePolicy)
		if err != nil {
			return nil, err
		}
		err = requests.IncrementRequestCount(signer, inActivePolicy) // Increment the rate limiter counter
		if err != nil {
			return nil, err
		}
		requests.RequestGarbageCollector.TrackRequest(reqHash, signer) // Track the request for garbage collection
		requestCounter = requests.CreateAndStoreRequestCounter(
			&instructionMessage.Data,
			signer,
			config.Thresholds[utils.OpHashToString(instructionMessage.Data.OPType)][utils.OpHashToString(instructionMessage.Data.OPCommand)],
		)
	} else {
		var exists bool
		requestCounter, exists = requests.GetRequestCounterByHash(reqHash)
		if !exists {
			return nil, errors.New("requests counter has just been deleted")
		}
	}

	requestCounter.Lock()
	defer requestCounter.Unlock()
	requestCounter.AddRequestSignature(signer, instructionMessage.Signature)
	requestCounter.AddRequestVariableMessage(signer, instructionMessage.Data.AdditionalVariableMessage)

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
		// Request completed successfully, decrement rate limiter counter
		err := requests.DecrementRequestCount(requestCounter.Proposer, inActivePolicy)
		if err != nil {
			return nil, err
		}
	}

	// TODO: Again what do we put in the nonces beside the challenge?
	token, err := attestation.CreateAttestation(
		[]string{
			hex.EncodeToString(instructionMessage.Challenge[:]),
			strconv.FormatUint(utils.GetTimestampInMilliseconds(), 10),
		},
		attestation.OIDCTokenType,
	) // todo: add response to the attested value?
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
		Finalized: finalize,
	}, nil

}

func InstructionResult(instructionQuery *api.InstructionResultRequest) (*api.InstructionResultResponse, error) {
	// find the request that was finalized
	requestCounterFinalized, err := requests.GetFinalizedRequestWithId(instructionQuery.InstructionId)
	if err != nil {
		return nil, err
	}

	var instructionResultData []byte

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

	token, err := attestation.CreateAttestation(
		[]string{
			instructionQuery.Challenge,
			strconv.FormatUint(utils.GetTimestampInMilliseconds(), 10),
		},
		attestation.OIDCTokenType,
	) // todo: add response to the attested value?
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
	voteResults := make([]api.VoteResult, 0)
	instructionStatus := "inProgress"
	for _, instructionHash := range requestsWithId {
		requestCounter, exists := requests.GetRequestCounterByHash(instructionHash)
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
	token, err := attestation.CreateAttestation(
		[]string{
			instructionQuery.Challenge,
			strconv.FormatUint(utils.GetTimestampInMilliseconds(), 10),
		},
		attestation.OIDCTokenType,
	) // todo: add response to the attested value?
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
