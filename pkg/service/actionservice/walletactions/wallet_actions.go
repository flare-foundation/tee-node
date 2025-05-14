package walletactions

import (
	api "tee-node/api/types"
	"tee-node/pkg/utils"
	"tee-node/pkg/wallets"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

// -------------------------------------------------------------------------

func Pause(message api.PauseWalletMessage, signatures [][]byte) error {
	isPaused, err := IsWalletPaused(message.WalletId, message.KeyId)
	if err != nil {
		return err
	}
	if isPaused {
		return errors.New("wallet is already paused")
	}

	pausingNonce, err := GetWalletPausingNonce(message.WalletId, message.KeyId)
	if err != nil {
		return err
	}
	if pausingNonce != message.PausingNonce {
		return errors.New("pausing nonce mismatch")
	}

	_, _, err = checkWalletExists(message.WalletId, message.KeyId)
	if err != nil {
		return err
	}

	pausingAddresses, err := GetWalletPausingAddresses(message.WalletId, message.KeyId)
	if err != nil {
		return err
	}

	err = utils.VerifyPauserSignature(message, pausingAddresses, signatures)
	if err != nil {
		return err
	}

	err = PauseWalletInternal(message.WalletId, message.KeyId)
	if err != nil {
		return err
	}
	return nil
}

func Resume(message api.ResumeWalletMessage, signatures [][]byte) error {
	isPaused, err := IsWalletPaused(message.WalletId, message.KeyId)
	if err != nil {
		return err
	}
	if !isPaused {
		return errors.New("wallet is not paused")
	}

	pausingNonce, err := GetWalletPausingNonce(message.WalletId, message.KeyId)
	if err != nil {
		return err
	}
	if pausingNonce != message.PausingNonce {
		return errors.New("pausing nonce mismatch")
	}

	adminsAddresses, adminsThreshold, err := checkWalletExists(message.WalletId, message.KeyId)
	if err != nil {
		return err
	}

	valid, err := verifyThresholdIsMet(message, adminsAddresses, signatures, adminsThreshold)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("threshold not met")
	}

	err = UnpauseWalletInternal(message.WalletId, message.KeyId)
	if err != nil {
		return err
	}

	return nil
}

func SetPausingAddresses(message api.PausingAddressSetWalletMessage, signatures [][]byte) error {
	isPaused, err := IsWalletPaused(message.WalletId, message.KeyId)
	if err != nil {
		return err
	}
	if isPaused {
		return errors.New("wallet is paused")
	}

	adminsAddresses, adminsThreshold, err := checkWalletExists(message.WalletId, message.KeyId)
	if err != nil {
		return err
	}

	valid, err := verifyThresholdIsMet(message, adminsAddresses, signatures, adminsThreshold)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("threshold not met")
	}

	err = updatePausingAddresses(message)
	if err != nil {
		return err
	}

	return nil
}

func updatePausingAddresses(message api.PausingAddressSetWalletMessage) error {
	lastPauserAddressSetupNonce, err := GetWalletPausingAddressSetupNonce(message.WalletId, message.KeyId)
	if err != nil {
		return err
	}
	// If lastPauserAddressSetupNonce >= setting.PauserAddressSetupNonce, return an error
	if lastPauserAddressSetupNonce.Cmp(&message.PauserAddressSetupNonce) != -1 {
		return errors.New("pauser address setup nonce mismatch")
	}

	err = UpdatePausingAddressesWalletInternal(message.WalletId, message.KeyId, message.PausingAddresses, message.PauserAddressSetupNonce)
	if err != nil {
		return err
	}
	return nil
}

func checkWalletExists(walletId common.Hash, keyId uint64) ([]common.Address, int, error) {
	wallet, err := wallets.GetWallet(wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId})
	if err != nil {
		return nil, 0, err
	}

	adminsAddresses := make([]common.Address, len(wallet.AdminsPublicKeys))
	for i, key := range wallet.AdminsPublicKeys {
		adminsAddresses[i] = crypto.PubkeyToAddress(*key)
	}

	return adminsAddresses, int(wallet.AdminsThreshold), nil
}

func verifyThresholdIsMet(message api.Hashable, adminsAddresses []common.Address, signatures [][]byte, adminsThreshold int) (bool, error) {
	messageHash, err := message.Hash()
	if err != nil {
		return false, err
	}

	isThresholdMet, err := utils.VerifyThresholdSignatures(messageHash[:], adminsAddresses, signatures, uint8(adminsThreshold))
	if err != nil {
		return false, err
	}
	if !isThresholdMet {
		return false, errors.New("threshold not met")
	}

	return true, nil
}
