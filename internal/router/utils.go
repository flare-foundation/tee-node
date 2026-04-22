package router

import (
	"errors"

	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/types"
)

// SignResult signs the action result payload and returns an action response.
func SignResult(ar *types.ActionResult, signer node.Signer) (*types.ActionResponse, error) {
	res := &types.ActionResponse{
		Result: *ar,
	}

	sig, err := signer.Sign(ar.Hash())
	if err != nil {
		res.Result.Log = "could not sign response"
		return res, errors.New("could not sign")
	}

	res.Signature = sig

	return res, nil
}
