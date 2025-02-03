package wallets

import (
	"tee-node/internal/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/pkg/errors"
)

type WalletSplit struct {
	Address common.Address
	Share   utils.ShamirShare
}

func SplitWallet(wallet *Wallet, numShares, threshold int) ([]*WalletSplit, error) {
	shares, err := utils.SplitToShamirShares(wallet.PrivateKey.D, numShares, threshold)
	if err != nil {
		return nil, err
	}

	splits := make([]*WalletSplit, numShares)

	for i, share := range shares {
		splits[i] = &WalletSplit{Address: wallet.Address, Share: share}
	}

	return splits, nil
}

func JointWallet(splits []*WalletSplit, address common.Address, threshold int) (*Wallet, error) {
	if len(splits) < threshold {
		return nil, errors.New("not enough splits")
	}

	candidatesIndexes := make([]int, 0)
	for i, split := range splits {
		if split.Address.Hex() == address.Hex() && split.Share.Threshold == threshold {
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

		return &Wallet{PrivateKey: privateKey, Address: address}, nil
	}

	return nil, errors.New("unable to join shares")
}
