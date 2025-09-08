package wallets

import (
	"encoding/json"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/pkg/types"
)

func ParseKeyGenerate(instructionData *instruction.DataFixed) (wallet.ITeeWalletKeyManagerKeyGenerate, error) {
	arg := wallet.MessageArguments[op.KeyGenerate]

	var unpacked wallet.ITeeWalletKeyManagerKeyGenerate
	err := structs.DecodeTo(arg, instructionData.OriginalMessage, &unpacked)
	if err != nil {
		return wallet.ITeeWalletKeyManagerKeyGenerate{}, err
	}

	return unpacked, nil
}

func CheckKeyGenerate(newWalletRequest wallet.ITeeWalletKeyManagerKeyGenerate) error {
	if len(newWalletRequest.ConfigConstants.AdminsPublicKeys) == 0 {
		return errors.New("no admin public keys")
	}

	return nil
}

func ParseKeyDelete(instructionData *instruction.DataFixed) (wallet.ITeeWalletKeyManagerKeyDelete, error) {
	arg := wallet.MessageArguments[op.KeyDelete]
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

func ParseKeyDataProviderRestore(instructionData *instruction.DataFixed) (wallet.ITeeWalletBackupManagerKeyDataProviderRestore, error) {
	arg := wallet.MessageArguments[op.KeyDataProviderRestore]
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

type KeyIDPair struct {
	WalletID common.Hash
	KeyID    uint64
}

type TEEBackupResponse struct {
	BackupID     WalletBackupID
	WalletBackup []byte
}

type WalletBackupID struct {
	TeeID     common.Address  `json:"teeId"`
	WalletID  common.Hash     `json:"walletId"`
	KeyID     uint64          `json:"keyId"`
	PublicKey types.PublicKey `json:"publicKey"`

	OPType        common.Hash `json:"opType"`
	RewardEpochID uint32      `json:"rewardEpochId"`
	RandomNonce   common.Hash `json:"randomNonce"`
}

func (wid *WalletBackupID) Hash() common.Hash {
	backupIdBytes, _ := json.Marshal(wid) //nolint:errchkjson // passed argument is safe
	hash := crypto.Keccak256Hash(backupIdBytes)

	return hash
}

type SignedKeyExistenceProof struct {
	KeyExistence hexutil.Bytes `json:"keyExistence"`
	Signature    hexutil.Bytes `json:"signature"`
}

func ExtractKeyExistence(b []byte) (*wallet.ITeeWalletKeyManagerKeyExistence, error) {
	var wskep SignedKeyExistenceProof

	err := json.Unmarshal(b, &wskep)
	if err != nil {
		return nil, err
	}

	keyExistence, err := structs.Decode[wallet.ITeeWalletKeyManagerKeyExistence](wallet.KeyExistenceStructArg, wskep.KeyExistence)
	if err != nil {
		return nil, err
	}

	return &keyExistence, nil
}

type KeyDataProviderRestoreResultStatus struct {
	ErrorPositions []int
	ErrorLogs      []string
}
