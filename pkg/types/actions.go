package types

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type ActionType string

const (
	Instruction ActionType = "instruction"
	Direct      ActionType = "direct"
)

type SubmissionTag string

const (
	// Submission tags for instruction action
	Threshold SubmissionTag = "threshold"
	End       SubmissionTag = "end"
	Submit    SubmissionTag = "submit"
)

type Action struct {
	Data                       ActionData      `json:"data"`
	AdditionalVariableMessages []hexutil.Bytes `json:"additionalVariableMessages"`
	Timestamps                 []uint64        `json:"timestamps"`
	AdditionalActionData       hexutil.Bytes   `json:"additionalActionData"`
	Signatures                 []hexutil.Bytes `json:"signatures"`
}

type ActionData struct {
	ID            common.Hash   `json:"id"`
	Type          ActionType    `json:"type"`
	SubmissionTag SubmissionTag `json:"submissionTag"`
	Message       hexutil.Bytes `json:"message"`
}

type ActionResponse struct {
	Result    ActionResult  `json:"result"`
	Signature hexutil.Bytes `json:"signature"`
}

// The response received after queuing an action
type ActionResult struct {
	ID            common.Hash   `json:"id"`
	SubmissionTag SubmissionTag `json:"submissionTag"`
	Status        bool          `json:"status"`
	Log           string        `json:"log"`

	OPType                 common.Hash   `json:"opType"`
	OPCommand              common.Hash   `json:"opCommand"`
	AdditionalResultStatus hexutil.Bytes `json:"additionalResultStatus"`

	Version string        `json:"version"`
	Data    hexutil.Bytes `json:"data"`
}

type ActionInfo struct {
	QueueId       string        `json:"queueId"`
	ActionId      common.Hash   `json:"actionId"`
	SubmissionTag SubmissionTag `json:"submissionTag"`
}

type RewardingData struct {
	VoteSequence   VoteSequence  `json:"voteSequence"`
	AdditionalData hexutil.Bytes `json:"additionalData"`
	Version        string        `json:"version"`
	Signature      hexutil.Bytes `json:"signature"` // TEE signature of voteHash
}

type VoteSequence struct {
	VoteHash                   common.Hash     `json:"voteHash"`
	InstructionId              common.Hash     `json:"instructionId"`
	InstructionHash            common.Hash     `json:"instructionHash"`
	RewardEpochId              uint32          `json:"rewardEpochId"`
	TeeId                      common.Address  `json:"teeId"`
	Signatures                 []hexutil.Bytes `json:"signatures"` // Signatures of the signers and cosigners
	AdditionalVariableMessages []hexutil.Bytes `json:"additionalVariableMessages"`
	Timestamps                 []uint64        `json:"timestamps"`
}
