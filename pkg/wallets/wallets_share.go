package wallets

import (
	"math/big"
	"tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/pkg/errors"
)

// WalletShare represents a share of a wallet's private key for backup purposes.
type WalletShare struct {
	BackupId  *big.Int
	WalletId  common.Hash
	KeyId     *big.Int
	Address   common.Address
	Share     utils.ShamirShare
	Threshold int
	NumShares int
}

// SplitWalletById splits a wallet's private key into multiple shares using Shamir's Secret Sharing.
// Parameters:
// - idTriple: A struct containing BackupId, WalletId, and KeyId to identify the wallet.
// - numShares: The number of shares to split the wallet into.
// - threshold: The minimum number of shares required to reconstruct the wallet.
func SplitWalletById(idTriple BackupWalletKeyIdTriple, numShares, threshold int) ([]*WalletShare, error) {
	wallet, err := GetWallet(WalletKeyIdPair{WalletId: idTriple.WalletId, KeyId: idTriple.KeyId})
	if err != nil {
		return nil, err
	}

	return SplitWallet(wallet, idTriple.BackupId, numShares, threshold)
}

// SplitWallet splits a wallet's private key into multiple shares using Shamir's Secret Sharing.
// Parameters:
// - wallet: The wallet whose private key is to be split.
// - backupId: The ID for the backup process.
// - numShares: The number of shares to split the wallet into.
// - threshold: The minimum number of shares required to reconstruct the wallet.
func SplitWallet(wallet *Wallet, backupId *big.Int, numShares, threshold int) ([]*WalletShare, error) {
	shares, err := utils.SplitToShamirShares(wallet.PrivateKey.D, numShares, threshold)
	if err != nil {
		return nil, err
	}

	splits := make([]*WalletShare, numShares)

	for i, share := range shares {
		splits[i] = &WalletShare{
			WalletId:  wallet.WalletId,
			KeyId:     wallet.KeyId,
			BackupId:  backupId,
			Address:   wallet.Address,
			Share:     share,
			Threshold: threshold,
			NumShares: numShares,
		}
	}

	return splits, nil
}

// JointWallet reconstructs a wallet from its shares using Shamir's Secret Sharing.
// Parameters:
// - splits: The shares used to reconstruct the wallet.
// - idTriple: A struct containing BackupId, WalletId, and KeyId to identify the wallet.
// - address: The expected Ethereum address of the reconstructed wallet.
// - threshold: The minimum number of shares required to reconstruct the wallet.
func JointWallet(splits []*WalletShare, idTriple BackupWalletKeyIdTriple, address common.Address, threshold int) (*Wallet, error) {
	if len(splits) < threshold {
		return nil, errors.New("not enough splits")
	}

	candidatesIndexes := make([]int, 0)
	for i, split := range splits {
		if split.Address.Hex() == address.Hex() && split.WalletId.Hex() == idTriple.WalletId.Hex() && split.KeyId.String() == idTriple.KeyId.String() && split.BackupId.String() == idTriple.BackupId.String() && split.Threshold == threshold {
			candidatesIndexes = append(candidatesIndexes, i)
		}
	}
	if len(candidatesIndexes) < threshold {
		return nil, errors.New("not enough splits with proper parameters")
	}

	subsets := utils.GenerateSubsets(candidatesIndexes, threshold)
	for _, subset := range subsets {
		shamirShares := make([]utils.ShamirShare, threshold)
		for i, index := range subset {
			shamirShares[i] = splits[index].Share
		}

		privateKeyBigInt, err := utils.CombineShamirShares(shamirShares)
		if err != nil {
			logger.Errorf("private key reconstruction error: %v", err)
			continue
		}
		privateKey := crypto.ToECDSAUnsafe(privateKeyBigInt.Bytes())
		if crypto.PubkeyToAddress(privateKey.PublicKey).Hex() != address.Hex() {
			logger.Errorf("private key reconstruction error: result does not match address")
			continue
		}

		return &Wallet{WalletId: idTriple.WalletId, KeyId: idTriple.KeyId, PrivateKey: privateKey, Address: address}, nil
	}

	return nil, errors.New("unable to join shares")
}
