package types

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
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
	Result         ActionResult  `json:"result"`
	Signature      hexutil.Bytes `json:"signature"`
	ProxySignature hexutil.Bytes `json:"proxySignature"`
}

// The response received after queuing an action
type ActionResult struct {
	ID            common.Hash   `json:"id"`
	SubmissionTag SubmissionTag `json:"submissionTag"`
	Status        uint8         `json:"status"`
	Log           string        `json:"log"`

	OPType                 common.Hash   `json:"opType"`
	OPCommand              common.Hash   `json:"opCommand"`
	AdditionalResultStatus hexutil.Bytes `json:"additionalResultStatus"`

	Version string        `json:"version"`
	Data    hexutil.Bytes `json:"data"`
}

// Hash returns keccak256(keccak256(data) || id || keccak256(submissionTag) || status).
func (ar *ActionResult) Hash() []byte {
	dataHash := crypto.Keccak256(ar.Data)
	tagHash := crypto.Keccak256([]byte(ar.SubmissionTag))

	packed := make([]byte, 0, 32+32+32+1)
	packed = append(packed, dataHash...)
	packed = append(packed, ar.ID[:]...)
	packed = append(packed, tagHash...)
	packed = append(packed, ar.Status)

	return crypto.Keccak256(packed)
}

type ActionInfo struct {
	QueueID       string        `json:"queueId"`
	ActionID      common.Hash   `json:"actionId"`
	SubmissionTag SubmissionTag `json:"submissionTag"`
}

type RewardingData struct {
	VoteSequence   VoteSequence  `json:"voteSequence"`
	AdditionalData hexutil.Bytes `json:"additionalData"`
	Version        string        `json:"version"`
	Signature      hexutil.Bytes `json:"signature"` // TEE signature of voteHash
}

type VoteSequence struct {
	VoteHash                        common.Hash     `json:"voteHash"`
	InstructionID                   common.Hash     `json:"instructionId"`
	InstructionHash                 common.Hash     `json:"instructionHash"`
	RewardEpochID                   uint32          `json:"rewardEpochId"`
	TeeID                           common.Address  `json:"teeId"`
	Signatures                      []hexutil.Bytes `json:"signatures"` // Signatures of the signers and cosigners
	AdditionalVariableMessageHashes []common.Hash   `json:"additionalVariableMessageHashes"`
	Timestamps                      []uint64        `json:"timestamps"`
}
