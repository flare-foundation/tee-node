package wallets

import (
	"encoding/json"
	"errors"
	"math/big"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	csigning "github.com/flare-foundation/go-flare-common/pkg/signing"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
)

var EVMSignAlgo = utils.ToHash("keccak256-secp256k1-ecdsa")
var VRFAlgo = utils.ToHash("keccak256-secp256k1-vrf")
var XRPSignAlgo = utils.ToHash("sha512half-secp256k1-ecdsa")
var Algos = []common.Hash{EVMSignAlgo, XRPSignAlgo, VRFAlgo}
var XRPType = utils.ToHash("XRP")
var EVMType = utils.ToHash("EVM")

// ParseKeyGenerate decodes the key generation instruction payload.
func ParseKeyGenerate(instructionData *instruction.DataFixed) (wallet.IWalletKeyManagerKeyGenerate, error) {
	arg := wallet.MessageArguments[op.KeyGenerate]

	var unpacked wallet.IWalletKeyManagerKeyGenerate
	err := structs.DecodeTo(arg, instructionData.OriginalMessage, &unpacked)
	if err != nil {
		return wallet.IWalletKeyManagerKeyGenerate{}, err
	}

	return unpacked, nil
}

// CheckKeyGenerate performs basic validation on the key generation request.
func CheckKeyGenerate(newWalletRequest wallet.IWalletKeyManagerKeyGenerate, teeID common.Address) error {
	if newWalletRequest.TeeId != teeID {
		return errors.New("requested teeID does not match required")
	}

	if len(newWalletRequest.ConfigConstants.AdminsPublicKeys) == 0 {
		return errors.New("no admin public keys")
	}
	if newWalletRequest.ConfigConstants.AdminsThreshold == 0 {
		return errors.New("admins threshold cannot be zero")
	}

	if newWalletRequest.ConfigConstants.AdminsThreshold > uint64(len(newWalletRequest.ConfigConstants.AdminsPublicKeys)) {
		return errors.New("admins threshold cannot be greater than the number of admins")
	}

	// Reject duplicate admin public keys.
	seenAdmins := make(map[wallet.PublicKey]bool, len(newWalletRequest.ConfigConstants.AdminsPublicKeys))
	for _, key := range newWalletRequest.ConfigConstants.AdminsPublicKeys {
		if _, ok := seenAdmins[key]; ok {
			return errors.New("admin public key list contains duplicate keys")
		}
		seenAdmins[key] = true
	}

	if newWalletRequest.ConfigConstants.CosignersThreshold > uint64(len(newWalletRequest.ConfigConstants.Cosigners)) {
		return errors.New("cosigners threshold cannot be greater than the number of cosigners")
	}

	if utils.HasDuplicateAddresses(newWalletRequest.ConfigConstants.Cosigners) {
		return errors.New("cosigner list contains duplicate addresses")
	}

	if !slices.Contains(Algos, newWalletRequest.SigningAlgo) {
		return errors.New("signing algorithm not supported")
	}

	return nil
}

// ParseKeyDelete decodes the key deletion instruction payload.
func ParseKeyDelete(instructionData *instruction.DataFixed) (wallet.IWalletKeyManagerKeyDelete, error) {
	arg := wallet.MessageArguments[op.KeyDelete]
	var unpacked wallet.IWalletKeyManagerKeyDelete
	err := structs.DecodeTo(arg, instructionData.OriginalMessage, &unpacked)
	if err != nil {
		return wallet.IWalletKeyManagerKeyDelete{}, err
	}
	err = nonceCheck(unpacked.Nonce)
	if err != nil {
		return wallet.IWalletKeyManagerKeyDelete{}, err
	}

	return unpacked, nil
}

// ParseKeyDataProviderRestore decodes the key data provider restore payload.
func ParseKeyDataProviderRestore(instructionData *instruction.DataFixed) (wallet.IWalletBackupManagerKeyDataProviderRestore, error) {
	arg := wallet.MessageArguments[op.KeyDataProviderRestore]
	var unpacked wallet.IWalletBackupManagerKeyDataProviderRestore
	err := structs.DecodeTo(arg, instructionData.OriginalMessage, &unpacked)
	if err != nil {
		return wallet.IWalletBackupManagerKeyDataProviderRestore{}, err
	}

	err = nonceCheck(unpacked.Nonce)
	if err != nil {
		return wallet.IWalletBackupManagerKeyDataProviderRestore{}, err
	}

	return unpacked, nil
}

// ParseKeyDirectBackup decodes the key direct-backup instruction payload.
func ParseKeyDirectBackup(instructionData *instruction.DataFixed) (wallet.IWalletBackupManagerKeyDirectBackup, error) {
	arg := wallet.MessageArguments[op.KeyDirectBackup]
	var unpacked wallet.IWalletBackupManagerKeyDirectBackup
	if err := structs.DecodeTo(arg, instructionData.OriginalMessage, &unpacked); err != nil {
		return wallet.IWalletBackupManagerKeyDirectBackup{}, err
	}
	if err := nonceCheck(unpacked.MachinePathListNonce); err != nil {
		return wallet.IWalletBackupManagerKeyDirectBackup{}, err
	}
	return unpacked, nil
}

// ParseKeyDirectRestore decodes the key direct-restore instruction payload.
func ParseKeyDirectRestore(instructionData *instruction.DataFixed) (wallet.IWalletBackupManagerKeyDirectRestore, error) {
	arg := wallet.MessageArguments[op.KeyDirectRestore]
	var unpacked wallet.IWalletBackupManagerKeyDirectRestore
	if err := structs.DecodeTo(arg, instructionData.OriginalMessage, &unpacked); err != nil {
		return wallet.IWalletBackupManagerKeyDirectRestore{}, err
	}
	if err := nonceCheck(unpacked.DestinationNonce); err != nil {
		return wallet.IWalletBackupManagerKeyDirectRestore{}, err
	}
	if err := nonceCheck(unpacked.MachinePathListNonce); err != nil {
		return wallet.IWalletBackupManagerKeyDirectRestore{}, err
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
	WalletID common.Hash `json:"walletId"`
	KeyID    uint64      `json:"keyId"`
}

type TEEBackupResponse struct {
	BackupID     WalletBackupID `json:"backupId"`
	WalletBackup []byte         `json:"walletBackup"`
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
func (wid *WalletBackupID) Equal(w *WalletBackupID) error {
	widEncoded, err := wid.encodeABI()
	if err != nil {
		return err
	}
	wEncoded, err := w.encodeABI()
	if err != nil {
		return err
	}
	if !slices.Equal(widEncoded, wEncoded) {
		return errors.New("wallet ids do not match")
	}

	return nil
}

// encodeABI prepares the wallet backup identifier for encoding.
func (wid *WalletBackupID) encodeABI() ([]byte, error) {
	sStruct := wallet.IWalletBackupManagerBackupId{
		TeeId:         wid.TeeID,
		WalletId:      wid.WalletID,
		KeyId:         wid.KeyID,
		KeyType:       wid.KeyType,
		SigningAlgo:   wid.SigningAlgo,
		PublicKey:     wid.PublicKey,
		RewardEpochId: wid.RewardEpochID,
		RandomNonce:   wid.RandomNonce,
	}

	return structs.Encode(wallet.BackupIdStructArg, sStruct)
}

// Hash returns the keccak hash of the wallet backup identifier.
func (wid *WalletBackupID) Hash() (common.Hash, error) {
	backupIDBytes, err := wid.encodeABI()
	if err != nil {
		return common.Hash{}, err
	}

	hash := crypto.Keccak256Hash(backupIDBytes)

	return hash, nil
}

type SignedKeyExistenceProof struct {
	KeyExistence hexutil.Bytes `json:"keyExistence"`
	Signature    hexutil.Bytes `json:"signature"`
}

// ExtractKeyExistence parses a signed existence proof from bytes and
// verifies the TEE signature against the canonical chain-bound preimage
// signing.Payload{TeeKeyExistenceTag, chainID, KeyExistenceDataHash(proof)}.Hash().
// chainID must match the chain whose WalletKeyManagerFacet.confirmKey
// will recover the signer.
func ExtractKeyExistence(b []byte, teeID common.Address, chainID uint64) (*wallet.IWalletKeyManagerKeyExistence, error) {
	var wskep SignedKeyExistenceProof
	err := json.Unmarshal(b, &wskep)
	if err != nil {
		return nil, err
	}

	keyExistence, err := structs.Decode[wallet.IWalletKeyManagerKeyExistence](wallet.KeyExistenceStructArg, wskep.KeyExistence)
	if err != nil {
		return nil, err
	}

	dataHash, err := types.KeyExistenceDataHash(&keyExistence)
	if err != nil {
		return nil, err
	}
	hash, err := csigning.NewPayload(csigning.TEEKeyExistence, chainID, dataHash).Hash()
	if err != nil {
		return nil, err
	}
	if err := utils.VerifySignature(hash[:], wskep.Signature, teeID); err != nil {
		return nil, err
	}

	return &keyExistence, nil
}

type KeyDataProviderRestoreResultStatus struct {
	ErrorPositions []int
	ErrorLogs      []string
}

// NewKeyDataProviderRestoreResultStatus returns an empty restore result status tracker.
func NewKeyDataProviderRestoreResultStatus() *KeyDataProviderRestoreResultStatus {
	return &KeyDataProviderRestoreResultStatus{
		ErrorPositions: make([]int, 0),
		ErrorLogs:      make([]string, 0),
	}
}

// AddError records a decryption or validation error at the given signer index.
func (s *KeyDataProviderRestoreResultStatus) AddError(i int, err error) {
	s.ErrorPositions = append(s.ErrorPositions, i)
	s.ErrorLogs = append(s.ErrorLogs, err.Error())
}

// Empty reports whether no errors were recorded.
func (s *KeyDataProviderRestoreResultStatus) Empty() bool {
	return len(s.ErrorPositions) == 0
}
