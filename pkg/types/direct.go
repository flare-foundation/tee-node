package types

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type DirectInstruction struct {
	Data       DirectInstructionData `json:"data"`
	Signatures []hexutil.Bytes       `json:"signatures"`
}

type DirectInstructionData struct {
	OPType    common.Hash   `json:"opType"`
	OPCommand common.Hash   `json:"opCommand"`
	Message   hexutil.Bytes `json:"message"`
}
