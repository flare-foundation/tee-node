package types

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/pkg/errors"
)

type KeyGenerateAdditionalFixedMessage struct {
	Backups []string
}

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
	if len(newWalletRequest.AdminsPublicKeys) == 0 {
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

func ParseRecoverWalletRequest(instructionData *instruction.DataFixed) (wallet.ITeeWalletBackupManagerKeyMachineRestore, error) {
	arg := wallet.MessageArguments[wallet.KeyMachineRestore]
	var unpacked wallet.ITeeWalletBackupManagerKeyMachineRestore
	err := structs.DecodeTo(arg, instructionData.OriginalMessage, &unpacked)
	if err != nil {
		return wallet.ITeeWalletBackupManagerKeyMachineRestore{}, err
	}
	return unpacked, nil
}

type WalletInfoRequest struct {
	WalletId  common.Hash
	KeyId     uint64
	Challenge string
}

type WalletInfoResponse struct {
	PublicKey    ECDSAPublicKey // Full ECDSA public key
	EthAddress   string
	XrpPublicKey string // SEC1 encoded public key (x-coordinate)
	XrpAddress   string
	Token        string
}

type WalletGetBackupRequest struct {
	wallet.ITeeWalletBackupManagerKeyDataProviderRestore
	Challenge string
}

type WalletGetBackupResponse struct {
	WalletBackup []byte
	Token        string
}

type WalletUploadBackupRequest struct {
	WalletBackup []byte
	Challenge    string
}

type WalletUploadBackupResponse struct {
	Token string
}

type WalletGetBackupShareRequest struct {
	wallet.ITeeWalletBackupManagerKeyDataProviderRestore
	OwnerPublicKey ECDSAPublicKey
	Challenge      string
}

type WalletGetBackupShareResponse struct {
	AdminEncryptedWalletSplit    []byte
	ProviderEncryptedWalletSplit []byte
	Token                        string
}

type WalletUploadBackupShareRequest struct {
	wallet.ITeeWalletBackupManagerKeyDataProviderRestore

	DecryptedWalletSplit []byte
	IsAdmin              bool

	Challenge string
}

type WalletUploadBackupShareResponse struct {
	Token string
}
