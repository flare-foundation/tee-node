package vrfutils

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/tee-node/internal/node"
	walletstorage "github.com/flare-foundation/tee-node/internal/wallets"
	"github.com/flare-foundation/tee-node/pkg/processorutils"
	"github.com/flare-foundation/tee-node/pkg/types"
	wallets "github.com/flare-foundation/tee-node/pkg/wallets"
	"github.com/flare-foundation/tee-node/pkg/wallets/vrf"
)

type Processor struct {
	*walletstorage.Storage
	node.Identifier
}

// NewProcessor creates a VRF instruction processor backed by wallet storage.
func NewProcessor(identifier node.Identifier, wStorage *walletstorage.Storage) Processor {
	return Processor{
		Storage:    wStorage,
		Identifier: identifier,
	}
}

// ProveRandomness returns a VRF proof for the given wallet/key pair and nonce.
func (p *Processor) ProveRandomness(
	_ context.Context,
	_ types.SubmissionTag,
	dataFixed *instruction.DataFixed,
	_ []hexutil.Bytes,
	_ []common.Address,
	_ *policy.SigningPolicy,
) ([]byte, []byte, error) {
	req, err := types.ParseVRFInstruction(dataFixed)
	if err != nil {
		return nil, nil, err
	}
	if len(req.Nonce) == 0 {
		return nil, nil, errors.New("nonce is empty")
	}

	id := wallets.KeyIDPair{
		WalletID: common.Hash(req.WalletId),
		KeyID:    req.KeyId,
	}

	p.RLock()
	walletKey, err := p.Get(id)
	p.RUnlock()
	if err != nil {
		return nil, nil, err
	}

	switch walletKey.SigningAlgo {
	case wallets.VRFAlgo:
	default:
		return nil, nil, errors.New("wallet signing algorithm does not support vrf")
	}

	if err := processorutils.CheckMatchingCosigners(dataFixed.Cosigners, walletKey.Cosigners, dataFixed.CosignersThreshold, walletKey.CosignersThreshold); err != nil {
		return nil, nil, err
	}

	sk, err := crypto.ToECDSA(walletKey.PrivateKey)
	if err != nil {
		return nil, nil, err
	}

	proof, err := vrf.VerifiableRandomness(sk, req.Nonce)
	if err != nil {
		return nil, nil, err
	}

	response := types.ProveRandomnessResponse{
		WalletID: common.Hash(req.WalletId),
		KeyID:    req.KeyId,
		Nonce:    req.Nonce,
		Proof:    *proof,
	}

	encoded, err := json.Marshal(response)
	if err != nil {
		return nil, nil, err
	}

	return encoded, nil, nil
}
