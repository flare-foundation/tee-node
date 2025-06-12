package types

import (
	"github.com/ethereum/go-ethereum/common"
)

const (
	ThresholdReachedSubmissionTag SubmissionTag = "ThresholdReached"
	VotingClosedSubmissionTag     SubmissionTag = "VotingClosed"

	// Action types
	InstructionType = "instruction"
	ActionType      = "action"
)

type SignedAction struct {
	Data       ActionData `json:"data"`
	Signatures [][]byte   `json:"signatures"`
}

type ActionData struct {
	OPType    common.Hash `json:"opType"`
	OPCommand common.Hash `json:"opCommand"`
	Message   []byte      `json:"message"`
}

type QueuedAction struct {
	Data                               QueueActionData `json:"data"`
	AdditionalVariableMessages         [][]byte        `json:"additionalVariableMessages"`
	Timestamps                         []uint64        `json:"timestamps"`
	AdditionalActionData               [][]byte        `json:"additionalActionData"`
	Signatures                         [][]byte        `json:"signatures"`
	CosignerSignatures                 [][]byte        `json:"cosignerSignatures"`
	CosignerAdditionalVariableMessages [][]byte        `json:"cosignerAdditionalVariableMessages"`
}

type SubmissionTag string

type QueueActionData struct {
	ActionId      common.Hash   `json:"actionId"`
	Type          string        `json:"type"`
	SubmissionTag SubmissionTag `json:"submissionTag"`
	Message       []byte        `json:"message"`
}

// The response received after queuing the action
type QueueActionResponse struct {
	ActionId      common.Hash   `json:"actionId"`
	SubmissionTag SubmissionTag `json:"submissionTag"`

	Result QueueActionResult `json:"result"`
}

type QueueActionResult struct {
	Status                 bool        `json:"status"`
	Log                    string      `json:"log"`
	OPType                 common.Hash `json:"opType"`
	OPCommand              common.Hash `json:"opCommand"`
	AdditionalResultStatus []byte      `json:"additionalResultStatus"`

	ResultData QueueActionResultData `json:"resultData"`
}

type QueueActionResultData struct {
	Message                []byte   `json:"message"`
	Signature              []byte   `json:"signature"`
	DataProviderSignatures [][]byte `json:"dataProviderSignatures"`
	CosignerSignatures     [][]byte `json:"cosignerSignatures"`
}

type QueuedActionInfo struct {
	QueueId       string        `json:"queueId"`
	ActionId      common.Hash   `json:"actionId"`
	SubmissionTag SubmissionTag `json:"submissionTag"`
}
