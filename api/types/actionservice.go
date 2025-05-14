package types

import (
	"github.com/ethereum/go-ethereum/common"
)

type SignedAction struct {
	Challenge  common.Hash `json:"challenge"`
	Data       ActionData  `json:"data"`
	Signatures [][]byte    `json:"signatures"`
}

type ActionData struct {
	OPType    common.Hash `json:"opType"`
	OPCommand common.Hash `json:"opCommand"`
	Message   []byte      `json:"message"`
}

type ActionResponse struct {
	Data    []byte `json:"data"`
	Token   string `json:"token"`
	Success bool   `json:"success"`
}
