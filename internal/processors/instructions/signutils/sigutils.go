package signutils

import (
	"crypto/ecdsa"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
	"github.com/flare-foundation/go-flare-common/pkg/tee/xrpl"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing/secp256k1"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing/signer"
	"github.com/flare-foundation/tee-node/pkg/processorutils"
	"github.com/flare-foundation/tee-node/pkg/wallets"
)

// loadPrivateKeys fetches and validates private keys for the given keyIDs.
// Must be called with the storage read lock held.
func loadPrivateKeys(storage *wallets.Storage, walletID [32]byte, keyIDs []uint64, dataFixed *instruction.DataFixed) ([]*ecdsa.PrivateKey, error) {
	privateKeys := make([]*ecdsa.PrivateKey, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		idPair := wallets.KeyIDPair{WalletID: common.Hash(walletID), KeyID: keyID}
		key, err := storage.Get(idPair)
		if err != nil {
			return nil, err
		}

		if key.KeyType != wallets.XRPType {
			return nil, errors.New("key type does not allow the action")
		}
		if key.SigningAlgo != wallets.XRPAlgo {
			return nil, errors.New("key's signing algorithm does not allow the action")
		}
		if err := processorutils.CheckMatchingCosigners(dataFixed.Cosigners, key.Cosigners, dataFixed.CosignersThreshold, key.CosignersThreshold); err != nil {
			return nil, err
		}

		sk, err := crypto.ToECDSA(key.PrivateKey)
		if err != nil {
			return nil, err
		}
		privateKeys = append(privateKeys, sk)
	}
	return privateKeys, nil
}

// buildSignedTx constructs and signs a multisig XRPL transaction for the given
// fee schedule try index.
func buildSignedTx(inst payment.ITeePaymentsPaymentInstructionMessage, privateKeys []*ecdsa.PrivateKey, try int) (map[string]any, error) {
	tx, err := xrpl.PaymentTxFromInstruction(inst, try)
	if err != nil {
		return nil, err
	}

	if tx["TransactionType"] == "Payment" {
		if err := xrpl.CheckNativePayment(tx); err != nil {
			return nil, err
		}
	}

	signerItems := make([]*signer.Signer, 0, len(privateKeys))
	for _, sk := range privateKeys {
		sigItem, err := secp256k1.SignTxMultisig(tx, sk)
		if err != nil {
			return nil, err
		}
		signerItems = append(signerItems, sigItem)
	}

	signerItems, check := signer.Sort(signerItems)
	if len(check) != 0 {
		return nil, errors.New("invalid signer item") // cannot happen
	}

	return signing.JoinMultisigJSON(tx, signerItems), nil
}
