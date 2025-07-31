package getutils

import (
	"encoding/json"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"

	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/wallets"
	"github.com/flare-foundation/tee-node/pkg/types"
)

func GetKeyInfoPackage() ([]byte, error) {
	myTeeId := node.TeeID()

	wallets.Storage.RLock()
	storedWallets := wallets.Storage.GetWallets()
	wallets.Storage.RUnlock()

	signedProofs := make([]types.WalletSignedKeyExistenceProof, len(storedWallets))
	for i, storedWallet := range storedWallets {
		existenceProof := wallets.WalletToKeyExistenceProof(storedWallet, myTeeId)
		existenceProofEncoded, err := structs.Encode(wallet.KeyExistenceStructArg, existenceProof)
		if err != nil {
			return nil, err
		}
		hash := crypto.Keccak256Hash(existenceProofEncoded)
		signature, err := node.Sign(hash[:])
		if err != nil {
			return nil, err
		}

		signedProofs[i] = types.WalletSignedKeyExistenceProof{
			KeyExistence: existenceProofEncoded,
			Signature:    signature,
		}
	}

	resultEncoded, err := json.Marshal(signedProofs)
	if err != nil {
		return nil, err
	}

	return resultEncoded, nil
}
