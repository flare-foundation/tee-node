package types

import (
	"encoding/json"

	"github.com/ethereum/go-ethereum/crypto"
)

// * ——————————————— POST Requests ——————————————— * //

const (
	InstructionRequest RequestType = iota
	SignPolicyRequest
)

type RequestType int

type Instruction struct {
	Challenge string
	Data      *InstructionData
	Signature []byte
}

type InstructionData struct {
	InstructionId string
	TeeId         string
	RewardEpochid uint32
	OpType        string
	OpCommand     string
	// Original binary message from smart contract event
	OriginalMessage []byte
	// Binary data, depending on operation type and instruction. Go JSON marshaled. (Fixed, because it's the same for all providers)
	AdditionalFixedMessage []byte
	// Binary data, —||—. (Variable, because it's different for each provider. Example: signature of AdditionalFixedMessage, or price prediction)
	AdditionalVariableMessage []byte `json:"-"` // Hide the field in json encoding
}

func (d InstructionData) Identifier() string {
	return d.InstructionId
}

func (data InstructionData) Hash() []byte {
	result, err := json.Marshal(data) // Encode without the field
	if err != nil {
		return nil
	}
	// TODO: Test if this really ignores AdditionalVariableMessage

	return crypto.Keccak256(result)
}

func (d InstructionData) RequestType() RequestType {
	return InstructionRequest
}

func (d InstructionData) RewardEpochId() uint32 {
	return d.RewardEpochid
}

type InstructionResponse struct {
	ResponseBase
	Data      []byte // TODO: is it needed?
	Finalized bool   // Note: leaving this in for now, because it's used in the tests
}

// * ——————————————— GET Requests ——————————————— * //

type InstructionResultRequest struct {
	Challenge     string
	InstructionId string
}

type InstructionResultResponse struct {
	ResponseBase
	Data []byte
}

type InstructionStatusResponse struct {
	ResponseBase
	Data InstrutionStatusData
}

type InstrutionStatusData struct {
	VoteResults []VoteResult
	Status      string
	ErrorLog    string
}

type VoteResult struct {
	NumberOfVotes uint16
	TotalWeight   uint16
}

type RewardingDataResponse struct {
	ResponseBase
	Data []byte
}
