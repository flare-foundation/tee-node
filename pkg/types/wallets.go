package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/constants"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/pkg/errors"
)

func ParseNewWalletRequest(instructionData *instruction.DataFixed) (wallet.ITeeWalletKeyManagerKeyGenerate, error) {
	arg := wallet.MessageArguments[constants.KeyGenerate]

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
	arg := wallet.MessageArguments[constants.KeyDelete]
	var unpacked wallet.ITeeWalletKeyManagerKeyDelete
	err := structs.DecodeTo(arg, instructionData.OriginalMessage, &unpacked)
	if err != nil {
		return wallet.ITeeWalletKeyManagerKeyDelete{}, err
	}
	err = nonceCheck(unpacked.Nonce)
	if err != nil {
		return wallet.ITeeWalletKeyManagerKeyDelete{}, err
	}

	return unpacked, nil
}

func ParseKeyDataProviderRestoreRequest(instructionData *instruction.DataFixed) (wallet.ITeeWalletBackupManagerKeyDataProviderRestore, error) {
	arg := wallet.MessageArguments[constants.KeyDataProviderRestore]
	var unpacked wallet.ITeeWalletBackupManagerKeyDataProviderRestore
	err := structs.DecodeTo(arg, instructionData.OriginalMessage, &unpacked)
	if err != nil {
		return wallet.ITeeWalletBackupManagerKeyDataProviderRestore{}, err
	}

	err = nonceCheck(unpacked.Nonce)
	if err != nil {
		return wallet.ITeeWalletBackupManagerKeyDataProviderRestore{}, err
	}

	return unpacked, nil
}

func nonceCheck(nonce *big.Int) error {
	if nonce == nil {
		return errors.New("nonce not given")
	}
	if nonce.BitLen() > 64 {
		return errors.New("nonce too big")
	}

	return nil
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
	RandomNonce   [32]byte
}

type WalletSignedKeyExistenceProof struct {
	KeyExistenceProof []byte
	Signature         []byte
}

type KeyDataProviderRestoreResultStatus struct {
	ErrorPositions []int
	ErrorLogs      []string
}
