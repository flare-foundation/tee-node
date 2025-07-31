package signutils

import (
	"encoding/json"
	"errors"

	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/wallets"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/xrpl"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing/secp256k1"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing/signer"
)

func SignPaymentTransaction(instructionData *instruction.DataFixed, signers []common.Address, isSignerDataProvider []bool) ([]byte, error) {
	originalMessage, err := types.ParseSignPaymentRequest(instructionData)
	if err != nil {
		return nil, err
	}

	tx := xrpl.PaymentTxFromInstruction(originalMessage)

	err = xrpl.CheckNativePayment(tx)
	if err != nil {
		return nil, err
	}

	keyIDs := make([]uint64, 0, 10)

	teeID := node.TeeID()

	for j := range originalMessage.TeeIdKeyIdPairs {
		if originalMessage.TeeIdKeyIdPairs[j].TeeId.Cmp(teeID) == 0 {
			keyIDs = append(keyIDs, originalMessage.TeeIdKeyIdPairs[j].KeyId)
		}
	}

	if len(keyIDs) == 0 {
		return nil, errors.New("no keys for signing")
	}

	signerItems := make([]*signer.Signer, 0, len(keyIDs))

	for j := range keyIDs {
		walletKeyIdPair := types.WalletKeyIdPair{WalletId: originalMessage.WalletId, KeyId: keyIDs[j]}

		wallets.Storage.RLock()
		key, err := wallets.Storage.GetWallet(walletKeyIdPair)
		wallets.Storage.RUnlock()
		if err != nil {
			return nil, err
		}

		_, err = utils.CheckCosigners(signers, isSignerDataProvider, key.Cosigners, key.CosignersThreshold)
		if err != nil {
			return nil, err
		}

		sigItem, err := secp256k1.SignTxMultisig(tx, key.PrivateKey)
		if err != nil {
			return nil, err
		}

		signerItems = append(signerItems, sigItem)
	}

	var check []*signer.Signer

	signerItems, check = signer.Sort(signerItems)
	if len(check) != 0 {
		return nil, errors.New("invalid signer item") // This can not happen.
	}

	tx = signing.JoinMultisigJson(tx, signerItems)

	jsonTx, err := json.Marshal(tx)
	if err != nil {
		return nil, err
	}

	return jsonTx, nil
}
