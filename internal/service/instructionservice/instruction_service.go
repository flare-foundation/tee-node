package instructionservice

import (
	"context"
	"encoding/hex"
	"slices"
	"sync"
	api "tee-node/api/types"
	"tee-node/internal/attestation"
	"tee-node/internal/config"
	"tee-node/internal/node"
	"tee-node/internal/policy"
	"tee-node/internal/requests"
	"tee-node/internal/service/instructionservice/walletsservice"

	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// instructionIdToHash handles the mapping needed to find all the instructions
// based on instruction Id
var instructionIdToHash = InitInstructionIdToHashes()

type InstructionIdToHashes struct {
	Map map[string][]string

	sync.Mutex
}

func InitInstructionIdToHashes() *InstructionIdToHashes {
	return &InstructionIdToHashes{Map: make(map[string][]string)}
}

// InstructionService handles forwarding JSON-RPC method calls to the appropriate service
type InstructionService struct {
}

// NewService initializes the InstructionService with registered services
func NewService() *InstructionService {
	return &InstructionService{}
}

// Call forwards the call to the appropriate service and method
func (s *InstructionService) SendSignedInstruction(ctx context.Context, instructionMessage *api.Instruction) (*api.InstructionResponse, error) {
	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "request cancelled")
	default:
	}

	// TODO: Is there any other check that should be done here?
	// Todo: Checks if InstructionId is valid, rewardEpochId is correct, etc.
	// TODO: Anti DOS checks
	err := CheckInstruction(instructionMessage.Data)
	if err != nil {
		return nil, err
	}

	requestCounter, thresholdReached, err := requests.ProcessRequest(*instructionMessage.Data, instructionMessage.Signature)
	if err != nil {
		return nil, err
	}
	processInstructionIdMapping(instructionMessage.Data)

	finalized := thresholdReached && !requestCounter.Done
	if finalized {

		switch instructionMessage.Data.OpType {

		case "REG":
			requestCounter.Result, err = handleRegPostRequest(instructionMessage.Data)

		case "WALLET":
			requestCounter.Result, err = handleWalletPostRequest(instructionMessage.Data, requestCounter.Signatures())

		case "XRP":
			requestCounter.Result, err = handleXrpPostRequest(instructionMessage.Data)

		case "BTC":
			requestCounter.Result, err = handleBtcPostRequest(instructionMessage.Data)

		case "FDC":
			requestCounter.Result, err = handleFdcPostRequest(instructionMessage.Data)

		default:
			return nil, status.Error(codes.InvalidArgument, "invalid operation type")
		}
		if err != nil {
			return nil, err
		}

		requestCounter.Done = true
	}

	// TODO: Again what do we put in the nonces beside the challenge?
	token, err := attestation.CreateAttestation([]string{instructionMessage.Challenge}, attestation.OIDCTokenType) // todo: add response to the attested value?
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
		Finalized: finalized,
	}, nil

}

func (s *InstructionService) InstructionResult(ctx context.Context, instructionQuery *api.InstructionResultRequest) (*api.InstructionResultResponse, error) {

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "request cancelled")
	default:
	}

	// find the request that was finalized
	instructionIdToHash.Lock()
	requestsWithId, ok := instructionIdToHash.Map[instructionQuery.InstructionId]
	instructionIdToHash.Unlock()
	if !ok {
		return nil, status.Error(codes.NotFound, "request not found")
	}

	var requestCounterFinalized *requests.RequestCounter[api.InstructionData]
	for _, instructionHash := range requestsWithId {
		requestCounter, err := requests.GetRequestCounter[api.InstructionData](instructionHash, api.InstructionRequest)
		if err != nil {
			return nil, status.Error(codes.NotFound, err.Error()) // TODO: is an error to strict here?
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

	switch requestCounterFinalized.Request.OpType {
	case "REG":
		instructionResultData, err = handleRegGetRequest(&requestCounterFinalized.Request, requestCounterFinalized.Result)

	case "WALLET":
		instructionResultData, err = handleWalletGetRequest(&requestCounterFinalized.Request, requestCounterFinalized.Result)

	case "XRP":
		instructionResultData, err = handleXrpGetRequest(&requestCounterFinalized.Request, requestCounterFinalized.Result)

	case "BTC":
		instructionResultData, err = handleBtcGetRequest(&requestCounterFinalized.Request, requestCounterFinalized.Result)

	case "FDC":
		instructionResultData, err = handleFdcGetRequest(&requestCounterFinalized.Request, requestCounterFinalized.Result)

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

func (s *InstructionService) InstructionStatus(ctx context.Context, instructionQuery *api.InstructionResultRequest) (*api.InstructionStatusResponse, error) {

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "request cancelled")
	default:
	}

	// find the request that was finalized
	instructionIdToHash.Lock()
	requestsWithId, ok := instructionIdToHash.Map[instructionQuery.InstructionId]
	instructionIdToHash.Unlock()
	if !ok {
		return nil, errors.New("request not found")
	}

	// var requestCounterFinalized *requests.RequestCounter[api.InstructionData]
	var voteResults []api.VoteResult = make([]api.VoteResult, 0)
	instructionStatus := "inProgress"
	for _, instructionHash := range requestsWithId {
		requestCounter, err := requests.GetRequestCounter[api.InstructionData](instructionHash, api.InstructionRequest)
		if err != nil {
			return nil, status.Error(codes.NotFound, err.Error()) // TODO: is an error to strict here?
		}

		requestPolicy, err := requestCounter.GetRequestPolicy()
		if err != nil {
			return nil, status.Error(codes.NotFound, err.Error())
		}

		voteResults = append(voteResults, api.VoteResult{
			NumberOfVotes: uint16(len(requestCounter.RequestSignatures)),
			TotalWeight:   requestCounter.CurrentWeight(requestPolicy),
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

// TODO: This shouldn't be here, but I don't know where else to put it for now
func (s *InstructionService) WalletInfo(ctx context.Context, req *api.WalletInfoRequest) (*api.WalletInfoResponse, error) {
	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "request cancelled")
	default:
	}

	return walletsservice.WalletInfo(req)
}

// * HELPERS * ==================================================== // Extract this to a separate file
func CheckInstruction(instructionData *api.InstructionData) error {
	nodeId := node.GetNodeId()
	if instructionData.TeeId != nodeId.Id {
		return errors.New("invalid TEE id")
	}

	if policy.ActiveSigningPolicy.RewardEpochId < instructionData.RewardEpochID {
		return errors.New("reward epoch not started yet")
	}
	if policy.ActiveSigningPolicy.RewardEpochId-instructionData.RewardEpochID > config.ACTIVE_POLICY_COUNT {
		return errors.New("reward epoch id too old")
	}

	// Check the command is valid
	valid := IsValidCommand(instructionData.OpType, instructionData.OpCommand)
	if !valid {
		return status.Error(codes.InvalidArgument, "invalid command for operation type")
	}

	return nil
}

// IsValidSubCommand checks if the OpType and Command is valid for a given operation type
func IsValidCommand(op, command string) bool {
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

func processInstructionIdMapping(instructionData *api.InstructionData) {
	instructionIdToHash.Lock()

	if _, ok := instructionIdToHash.Map[instructionData.InstructionId]; !ok {
		instructionIdToHash.Map[instructionData.InstructionId] = make([]string, 0)
	}

	instructionHash := hex.EncodeToString(instructionData.Hash())

	// If the instruction hash is already in the list, we don't need to add it again
	if slices.Contains(instructionIdToHash.Map[instructionData.InstructionId], instructionHash) {
		instructionIdToHash.Unlock()
		return
	}

	instructionIdToHash.Map[instructionData.InstructionId] = append(instructionIdToHash.Map[instructionData.InstructionId], instructionHash)
	instructionIdToHash.Unlock()
}
