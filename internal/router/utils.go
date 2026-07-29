package router

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	csigning "github.com/flare-foundation/go-flare-common/pkg/signing"
	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/pkg/types"
)

// SignResult signs the action result payload and returns an action response.
// The signature is over signing.Payload{TEEActionResultTag, chainID,
// ActionResult.Hash()}.Hash().
func SignResult(ar *types.ActionResult, signer node.IdentifierAndSigner) (*types.ActionResponse, error) {
	res := &types.ActionResponse{
		Result: *ar,
	}

	chainID, err := signer.ChainID()
	if err != nil {
		res.Result.Log = "could not get chain id"
		return res, errors.New("could not sign")
	}
	signHash, err := csigning.NewPayload(csigning.TEEActionResult, chainID, common.BytesToHash(ar.Hash())).Hash()
	if err != nil {
		res.Result.Log = "could not sign response"
		return res, errors.New("could not sign")
	}

	sig, err := signer.Sign(signHash[:])
	if err != nil {
		res.Result.Log = "could not sign response"
		return res, errors.New("could not sign")
	}

	res.Signature = sig

	return res, nil
}
