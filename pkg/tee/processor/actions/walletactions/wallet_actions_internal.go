package walletactions

// import (
// 	"math/big"
// 	"tee-node/pkg/tee/node"
// 	"tee-node/pkg/tee/wallets"

// 	"github.com/ethereum/go-ethereum/common"
// )

// func GetWalletPausingAddresses(walletId common.Hash, keyId uint64) ([]common.Address, error) {
// 	wallet, err := wallets.GetWallet(wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId})
// 	if err != nil {
// 		return nil, err
// 	}
// 	return wallet.WalletPauserAddresses, nil
// }

// func GetWalletPausingAddressSetupNonce(walletId common.Hash, keyId uint64) (big.Int, error) {
// 	wallet, err := wallets.GetWallet(wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId})
// 	if err != nil {
// 		return big.Int{}, err
// 	}
// 	return wallet.WalletPauserAddressSetupNonce, nil
// }

// func IsWalletPaused(walletId common.Hash, keyId uint64) (bool, error) {
// 	wallet, err := wallets.GetWallet(wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId})
// 	if err != nil {
// 		return false, err
// 	}
// 	return wallet.IsWalletPaused, nil
// }

// func GetWalletPausingNonce(walletId common.Hash, keyId uint64) (common.Hash, error) {
// 	wallet, err := wallets.GetWallet(wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId})
// 	if err != nil {
// 		return common.Hash{}, err
// 	}
// 	return wallet.WalletPausingNonce, nil
// }

// func PauseWalletInternal(walletId common.Hash, keyId uint64) error {
// 	wallet, err := wallets.GetWallet(wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId})
// 	if err != nil {
// 		return err
// 	}
// 	wallet.IsWalletPaused = true
// 	return nil
// }

// func UnpauseWalletInternal(walletId common.Hash, keyId uint64) error {
// 	wallet, err := wallets.GetWallet(wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId})
// 	if err != nil {
// 		return err
// 	}
// 	wallet.WalletPausingNonce = node.GeneratePausingNonce()
// 	wallet.IsWalletPaused = false
// 	return nil
// }

// func UpdatePausingAddressesWalletInternal(walletId common.Hash, keyId uint64, pausingAddresses []common.Address, pauserAddressSetupNonce big.Int) error {
// 	wallet, err := wallets.GetWallet(wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId})
// 	if err != nil {
// 		return err
// 	}
// 	wallet.WalletPauserAddresses = pausingAddresses
// 	wallet.WalletPauserAddressSetupNonce = pauserAddressSetupNonce
// 	return nil
// }
