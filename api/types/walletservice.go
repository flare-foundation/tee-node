package types

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/pkg/errors"
)

func ParseNewWalletRequest(instructionData *instruction.DataFixed) (wallet.ITeeWalletKeyManagerKeyGenerate, error) {
	arg := wallet.MessageArguments[wallet.KeyGenerate]

	var unpacked wallet.ITeeWalletKeyManagerKeyGenerate
	err := structs.DecodeTo(arg, instructionData.OriginalMessage, &unpacked)
	if err != nil {
		return wallet.ITeeWalletKeyManagerKeyGenerate{}, err
	}

	return unpacked, nil
}

func CheckNewWalletRequest(newWalletRequest wallet.ITeeWalletKeyManagerKeyGenerate) error {
	if len(newWalletRequest.ConfigConstants.AdminsPublicKeys) == 0 {
		return errors.New("no admin public keys")
	}

	return nil
}

func ParseDeleteWalletRequest(instructionData *instruction.DataFixed) (wallet.ITeeWalletKeyManagerKeyDelete, error) {
	arg := wallet.MessageArguments[wallet.KeyDelete]
	var unpacked wallet.ITeeWalletKeyManagerKeyDelete
	err := structs.DecodeTo(arg, instructionData.OriginalMessage, &unpacked)
	if err != nil {
		return wallet.ITeeWalletKeyManagerKeyDelete{}, err
	}

	return unpacked, nil
}

func ParseKeyDataProviderRestoreRequest(instructionData *instruction.DataFixed) (wallet.ITeeWalletBackupManagerKeyDataProviderRestore, error) {
	arg := wallet.MessageArguments[wallet.KeyDataProviderRestore]
	var unpacked wallet.ITeeWalletBackupManagerKeyDataProviderRestore
	err := structs.DecodeTo(arg, instructionData.OriginalMessage, &unpacked)
	if err != nil {
		return wallet.ITeeWalletBackupManagerKeyDataProviderRestore{}, err
	}

	return unpacked, nil
}

type WalletGetBackupResponse struct {
	BackupId     WalletBackupId
	WalletBackup []byte
}

type WalletBackupId struct {
	TeeId     common.Address
	WalletId  common.Hash
	KeyId     uint64
	PublicKey ECDSAPublicKey

	OpType        [32]byte
	RewardEpochID uint32
}
