package router

import (
	"encoding/json"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/types"
)

type rID struct {
	OPType    common.Hash `json:"opType"`
	OPCommand common.Hash `json:"opCommand"`
}

// routID extracts routID from the action.
func routID(a *types.Action) (rID, error) {
	var id rID
	err := json.Unmarshal(a.Data.Message, &id)
	return id, err
}

func (i rID) String() string {
	return string(op.HashToOPType(i.OPType)) + ", " + string(op.HashToOPCommand(i.OPCommand))
}

func SignResult(ar *types.ActionResult, signer node.Signer) (*types.ActionResponse, error) {
	res := &types.ActionResponse{
		Result: *ar,
	}

	msgHash := crypto.Keccak256(ar.Data)
	sig, err := signer.Sign(msgHash)
	if err != nil {
		res.Result.Log = "could not sign response"
		return res, errors.New("could not sign")
	}

	res.Signature = sig

	return res, nil
}
