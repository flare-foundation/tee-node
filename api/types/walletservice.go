package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
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

func NewDeleteWalletRequest(instructionData *instruction.DataFixed) (wallet.ITeeWalletKeyManagerKeyDelete, error) {

	arg := wallet.MessageArguments[wallet.KeyDelete]
	var unpacked wallet.ITeeWalletKeyManagerKeyDelete
	err := structs.DecodeTo(arg, instructionData.OriginalMessage, &unpacked)
	if err != nil {
		return wallet.ITeeWalletKeyManagerKeyDelete{}, err
	}

	return unpacked, nil
}

type SplitWalletAdditionalFixedMessage struct {
	PublicKeys []string
}

func NewSplitWalletRequest(instructionData *instruction.DataFixed) (wallet.ITeeWalletBackupManagerKeyMachineBackup, error) {

	arg := wallet.MessageArguments[wallet.KeyMachineBackup]

	var unpacked wallet.ITeeWalletBackupManagerKeyMachineBackup
	err := structs.DecodeTo(arg, instructionData.OriginalMessage, &unpacked)
	if err != nil {
		return wallet.ITeeWalletBackupManagerKeyMachineBackup{}, err
	}

	return unpacked, nil
}

type RecoverWalletRequestAdditionalFixedMessage struct {
	TeeIds    []common.Address
	ShareIds  []string
	Address   string
	Threshold int64
}

func NewRecoverWalletRequest(instructionData *instruction.DataFixed) (wallet.ITeeWalletBackupManagerKeyMachineRestore, error) {
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
	KeyId     *big.Int
	Challenge string
}

type WalletInfoResponse struct {
	EthPublicKey ECDSAPublicKey // Full ECDSA public key
	EthAddress   string
	XrpPublicKey string // SEC1 encoded public key (x-coordinate)
	XrpAddress   string
	Token        string
}
