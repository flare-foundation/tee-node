package signutils

import (
	"encoding/json"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/xrpl"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing/secp256k1"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing/signer"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/processorutils"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/wallets"
)

type Processor struct {
	*wallets.Storage
	node.Identifier
}

func NewProcessor(identifier node.Identifier, wStorage *wallets.Storage) Processor {
	return Processor{
		Storage:    wStorage,
		Identifier: identifier,
	}
}

func (p *Processor) SignXRPLPayment(
	_ types.SubmissionTag,
	dataFixed *instruction.DataFixed,
	_ []hexutil.Bytes,
	_ []common.Address,
	_ *policy.SigningPolicy,
) ([]byte, []byte, error) {
	inst, err := types.ParsePaymentInstruction(dataFixed)
	if err != nil {
		return nil, nil, err
	}

	tx := xrpl.PaymentTxFromInstruction(inst)
	err = xrpl.CheckNativePayment(tx)
	if err != nil {
		return nil, nil, err
	}

	keyIDs := make([]uint64, 0, 10)
	teeID := p.TeeID()
	for j := range inst.TeeIdKeyIdPairs {
		if inst.TeeIdKeyIdPairs[j].TeeId.Cmp(teeID) == 0 {
			keyIDs = append(keyIDs, inst.TeeIdKeyIdPairs[j].KeyId)
		}
	}

	if len(keyIDs) == 0 {
		return nil, nil, errors.New("no keys for signing")
	}

	signerItems := make([]*signer.Signer, 0, len(keyIDs))
	for j := range keyIDs {
		walletKeyIdPair := wallets.KeyIDPair{WalletID: inst.WalletId, KeyID: keyIDs[j]}

		key, err := p.Get(walletKeyIdPair)
		if err != nil {
			return nil, nil, err
		}

		err = processorutils.CheckMatchingCosigners(dataFixed.Cosigners, key.Cosigners, dataFixed.CosignersThreshold, key.CosignersThreshold)
		if err != nil {
			return nil, nil, err
		}

		sigItem, err := secp256k1.SignTxMultisig(tx, key.PrivateKey)
		if err != nil {
			return nil, nil, err
		}

		signerItems = append(signerItems, sigItem)
	}

	var check []*signer.Signer
	signerItems, check = signer.Sort(signerItems)
	if len(check) != 0 {
		return nil, nil, errors.New("invalid signer item") // This can not happen.
	}

	tx = signing.JoinMultisigJson(tx, signerItems)

	jsonTx, err := json.Marshal(tx)
	if err != nil {
		return nil, nil, err
	}

	return jsonTx, nil, nil
}
