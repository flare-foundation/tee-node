package wallets

import (
	"tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/pkg/errors"
)

type WalletShare struct {
	BackupId  string
	WalletId  string
	KeyId     string
	Address   common.Address
	Share     utils.ShamirShare
	Threshold int
	NumShares int
}

func SplitWalletById(idTriple BackupWalletKeyIdTriple, numShares, threshold int) ([]*WalletShare, error) {
	wallet, err := GetWallet(WalletKeyIdPair{WalletId: idTriple.WalletId, KeyId: idTriple.KeyId})
	if err != nil {
		return nil, err
	}

	return SplitWallet(wallet, idTriple.BackupId, numShares, threshold)
}

func SplitWallet(wallet *Wallet, backupId string, numShares, threshold int) ([]*WalletShare, error) {
	shares, err := utils.SplitToShamirShares(wallet.PrivateKey.D, numShares, threshold)
	if err != nil {
		return nil, err
	}

	splits := make([]*WalletShare, numShares)

	for i, share := range shares {
		splits[i] = &WalletShare{WalletId: wallet.WalletId,
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

func JointWallet(splits []*WalletShare, idTriple BackupWalletKeyIdTriple, address common.Address, threshold int) (*Wallet, error) {
	if len(splits) < threshold {
		return nil, errors.New("not enough splits")
	}

	candidatesIndexes := make([]int, 0)
	for i, split := range splits {
		if split.Address.Hex() == address.Hex() && split.WalletId == idTriple.WalletId && split.KeyId == idTriple.KeyId && split.BackupId == idTriple.BackupId && split.Threshold == threshold {
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
			logger.Errorf("private key reconstruction error: %v")
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
