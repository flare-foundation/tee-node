package wallets

import (
	"encoding/json"
	"errors"
	"math/big"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/pkg/utils"
)

var EVMAlgo = utils.ToHash("keccak256-secp256k1-ecdsa")
var XRPAlgo = utils.ToHash("sha512half-secp256k1-ecdsa")
var SigningAlgos = []common.Hash{EVMAlgo, XRPAlgo}
var XRPType = utils.ToHash("XRP")
var EVMType = utils.ToHash("EVM")

// ParseKeyGenerate decodes the key generation instruction payload.
func ParseKeyGenerate(instructionData *instruction.DataFixed) (wallet.ITeeWalletKeyManagerKeyGenerate, error) {
	arg := wallet.MessageArguments[op.KeyGenerate]

	var unpacked wallet.ITeeWalletKeyManagerKeyGenerate
	err := structs.DecodeTo(arg, instructionData.OriginalMessage, &unpacked)
	if err != nil {
		return wallet.ITeeWalletKeyManagerKeyGenerate{}, err
	}

	return unpacked, nil
}

// CheckKeyGenerate performs basic validation on the key generation request.
func CheckKeyGenerate(newWalletRequest wallet.ITeeWalletKeyManagerKeyGenerate, teeID common.Address) error {
	if newWalletRequest.TeeId != teeID {
		return errors.New("requested teeID does not match required")
	}

	if len(newWalletRequest.ConfigConstants.AdminsPublicKeys) == 0 {
		return errors.New("no admin public keys")
	}

	if !slices.Contains(SigningAlgos, newWalletRequest.SigningAlgo) {
		return errors.New("signing algorithm not supported")
	}

	return nil
}

// ParseKeyDelete decodes the key deletion instruction payload.
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

// ParseKeyDataProviderRestore decodes the key data provider restore payload.
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
	if nonce.BitLen() > 256 {
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
	TeeID     common.Address `json:"teeId"`
	WalletID  common.Hash    `json:"walletId"`
	KeyID     uint64         `json:"keyId"`
	PublicKey hexutil.Bytes  `json:"publicKey"`

	KeyType       common.Hash `json:"keyType"`
	SigningAlgo   common.Hash `json:"signingAlgo"`
	RewardEpochID uint32      `json:"rewardEpochId"`
	RandomNonce   common.Hash `json:"randomNonce"`
}

// Equal checks if two wallet backup identifiers are equal.
// Will silently fail if either PublicKey is (absurdly) too large. The length should be checked beforehand.
func (wid *WalletBackupID) Equal(w *WalletBackupID) bool {
	return slices.Equal(wid.encodeABI(), w.encodeABI())
}

// encodeABI prepares the wallet backup identifier for encoding.
func (wid *WalletBackupID) encodeABI() []byte {
	sStruct := wallet.ITeeWalletBackupManagerBackupId{
		TeeId:         wid.TeeID,
		WalletId:      wid.WalletID,
		KeyId:         wid.KeyID,
		KeyType:       wid.KeyType,
		SigningAlgo:   wid.SigningAlgo,
		PublicKey:     wid.PublicKey,
		RewardEpochId: wid.RewardEpochID,
		RandomNonce:   wid.RandomNonce,
	}

	enc, _ := structs.Encode(wallet.BackupIdStructArg, sStruct)
	return enc
}

// Hash returns the keccak hash of the wallet backup identifier.
// Will silently fail if the PublicKey is (absurdly) too large. The length should be checked beforehand.
func (wid *WalletBackupID) Hash() common.Hash {
	backupIdBytes := wid.encodeABI()

	hash := crypto.Keccak256Hash(backupIdBytes)

	return hash
}

type SignedKeyExistenceProof struct {
	KeyExistence hexutil.Bytes `json:"keyExistence"`
	Signature    hexutil.Bytes `json:"signature"`
}

// ExtractKeyExistence parses a signed existence proof from bytes.
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
