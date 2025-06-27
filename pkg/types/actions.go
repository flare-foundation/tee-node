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

// The response received after queuing an action
type ActionResponse struct {
	ID            common.Hash   `json:"id"`
	SubmissionTag SubmissionTag `json:"submissionTag"`

	Result ActionResult `json:"result"`
}

type ActionResult struct {
	Status                 bool          `json:"status"`
	Log                    string        `json:"log"`
	OPType                 common.Hash   `json:"opType"`
	OPCommand              common.Hash   `json:"opCommand"`
	AdditionalResultStatus hexutil.Bytes `json:"additionalResultStatus"`

	ResultData ActionResultData `json:"resultData"`
}

type ActionResultData struct {
	Message   hexutil.Bytes `json:"message"`
	Signature hexutil.Bytes `json:"signature"`
}

type ActionInfo struct {
	QueueId       string        `json:"queueId"`
	ActionId      common.Hash   `json:"actionId"`
	SubmissionTag SubmissionTag `json:"submissionTag"`
}

type SignerSequence struct {
	Data      SignerSequenceData `json:"data"`
	Signature hexutil.Bytes      `json:"signature"` // TEE signature of QueueHash
}

type SignerSequenceData struct {
	VoteHash                   common.Hash     `json:"queueHash"`
	InstructionId              common.Hash     `json:"instructionId"`
	InstructionHash            common.Hash     `json:"instructionHash"`
	RewardEpochId              uint32          `json:"rewardEpochId"`
	TeeId                      common.Address  `json:"teeId"`
	Signatures                 []hexutil.Bytes `json:"signatures"` // Signatures of the signers and cosigners
	AdditionalVariableMessages []hexutil.Bytes `json:"additionalVariableMessages"`
	Timestamps                 []uint64        `json:"timestamps"`
}
