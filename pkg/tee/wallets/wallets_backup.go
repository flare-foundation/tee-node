package wallets

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"slices"
	"tee-node/api/types"
	"tee-node/pkg/tee/settings"
	"tee-node/pkg/tee/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/pkg/errors"
)

type WalletBackup struct {
	WalletBackupMetaData
	AdminEncryptedParts     *EncryptedShares
	ProvidersEncryptedParts *EncryptedShares
	Signature               []byte
}

type WalletBackupMetaData struct {
	WalletBackupId
	OpTypeConstants []byte

	AdminsPublicKeys   []types.ECDSAPublicKey
	AdminsThreshold    uint64
	ProvidersThreshold uint64
	Cosigners          []common.Address
	CosignersThreshold uint64
}

type WalletBackupId struct {
	TeeId     common.Address
	WalletId  common.Hash
	KeyId     uint64
	PublicKey types.ECDSAPublicKey

	OpType        [32]byte
	RewardEpochID uint32
}

type EncryptedShares struct {
	Splits           [][]byte
	OwnersPublicKeys []types.ECDSAPublicKey
	Threshold        uint64
	PublicKey        types.ECDSAPublicKey
	Weights          []uint16
}

type KeySplit struct {
	KeySplitData
	Signature []byte
}

type KeySplitData struct {
	Shares []utils.ShamirShare
	PartialWalletBackupId
	OwnerPublicKey types.ECDSAPublicKey
}

type PartialWalletBackupId struct {
	WalletBackupId
	PartialPubKey types.ECDSAPublicKey
	IsAdmin       bool
}

func (backupId *WalletBackupId) Hash() common.Hash {
	backupIdBytes, _ := json.Marshal(backupId) // todo: check that this cannot be error
	hash := crypto.Keccak256Hash(backupIdBytes)

	return hash
}

func (keySplitData *KeySplitData) HashForSigning() (common.Hash, error) {
	keyDataBytes, err := json.Marshal(keySplitData)
	if err != nil {
		return common.Hash{}, err
	}
	hash := crypto.Keccak256Hash(keyDataBytes)

	return hash, nil
}

func (keySplitData *KeySplitData) Sign(privKey *ecdsa.PrivateKey) ([]byte, error) {
	hash, err := keySplitData.HashForSigning()
	if err != nil {
		return nil, err
	}

	signature, err := utils.Sign(hash[:], privKey)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (keySplitData *KeySplit) VerifySignature() error {
	hash, err := keySplitData.HashForSigning()
	if err != nil {
		return err
	}

	pubKeyParsed, err := types.ParsePubKey(keySplitData.PublicKey)
	if err != nil {
		return err
	}
	mainKeyAddress := crypto.PubkeyToAddress(*pubKeyParsed)

	err = utils.VerifySignature(hash[:], keySplitData.Signature, mainKeyAddress)

	return err
}

func (walletBackup *WalletBackup) HashForSigning() (common.Hash, error) {
	type WalletBackupForHashing struct {
		WalletBackupMetaData
		AdminEncryptedParts     *EncryptedShares
		ProvidersEncryptedParts *EncryptedShares
	}

	walletBackupBytes, err := json.Marshal(WalletBackupForHashing{
		WalletBackupMetaData:    walletBackup.WalletBackupMetaData,
		AdminEncryptedParts:     walletBackup.AdminEncryptedParts,
		ProvidersEncryptedParts: walletBackup.ProvidersEncryptedParts,
	})
	if err != nil {
		return common.Hash{}, err
	}
	hash := crypto.Keccak256Hash(walletBackupBytes)

	return hash, nil
}

func (walletBackup *WalletBackup) Check() error {
	err := walletBackup.AdminEncryptedParts.Check()
	if err != nil {
		return err
	}
	err = walletBackup.ProvidersEncryptedParts.Check()
	if err != nil {
		return err
	}

	if walletBackup.AdminsThreshold != walletBackup.AdminEncryptedParts.Threshold {
		return errors.New("admin threshold not matching given data")
	}

	if walletBackup.ProvidersThreshold != walletBackup.ProvidersEncryptedParts.Threshold {
		return errors.New("providers threshold not matching given data")
	}

	if len(walletBackup.AdminsPublicKeys) != len(walletBackup.AdminEncryptedParts.OwnersPublicKeys) {
		return errors.New("length of admin public keys not matching given data")
	}

	for i, pubKey := range walletBackup.AdminsPublicKeys {
		if pubKey != walletBackup.AdminEncryptedParts.OwnersPublicKeys[i] {
			return errors.New("admin public keys not matching")
		}
	}

	return nil
}

func (e *EncryptedShares) Check() error {
	if len(e.Splits) != len(e.OwnersPublicKeys) {
		return errors.New("the number of splits does not match the number of public keys")
	}
	if len(e.Splits) != len(e.Weights) {
		return errors.New("the number of splits does not match the number of weights")
	}
	if uint64(utils.Sum(e.Weights)) < e.Threshold {
		return errors.New("threshold too high")
	}

	return nil
}

func BackupWallet(wallet *Wallet, providersPubKeys []*ecdsa.PublicKey, signingPolicyWeights []uint16, rewardEpochId uint32, teeId common.Address) (*WalletBackup, error) {
	adminsPubKeys := make([]types.ECDSAPublicKey, len(wallet.AdminsPublicKeys))
	for i, pubKey := range wallet.AdminsPublicKeys {
		adminsPubKeys[i] = types.PubKeyToStruct(pubKey)
	}
	normalizedWeights := settings.WeightsNormalization(signingPolicyWeights)

	metaData := WalletBackupMetaData{
		WalletBackupId: WalletBackupId{
			TeeId:         teeId,
			WalletId:      wallet.WalletId,
			KeyId:         wallet.KeyId,
			PublicKey:     types.PubKeyToStruct(&wallet.PrivateKey.PublicKey),
			OpType:        wallet.OpType,
			RewardEpochID: rewardEpochId,
		},
		AdminsPublicKeys:   adminsPubKeys,
		AdminsThreshold:    wallet.AdminsThreshold,
		ProvidersThreshold: settings.DataProvidersBackupThreshold,
		OpTypeConstants:    make([]byte, len(wallet.OpTypeConstants)),
		Cosigners:          make([]common.Address, len(wallet.Cosigners)),
		CosignersThreshold: wallet.CosignersThreshold,
	}
	copy(metaData.OpTypeConstants, wallet.OpTypeConstants)
	copy(metaData.Cosigners, wallet.Cosigners)

	splitKey, err := utils.SplitPrivateKey(wallet.PrivateKey, 2)
	if err != nil {
		return nil, err
	}

	weightsOne := utils.ConstantSlice(1, len(wallet.AdminsPublicKeys))
	adminEncryptedParts, err := SplitAndEncrypt(splitKey[0], wallet.AdminsPublicKeys, wallet.AdminsThreshold, weightsOne, metaData.WalletBackupId, wallet.PrivateKey, true)
	if err != nil {
		return nil, err
	}

	providersEncryptedParts, err := SplitAndEncrypt(splitKey[1], providersPubKeys, settings.DataProvidersBackupThreshold, normalizedWeights, metaData.WalletBackupId, wallet.PrivateKey, false)
	if err != nil {
		return nil, err
	}

	walletBackup := &WalletBackup{
		WalletBackupMetaData:    metaData,
		AdminEncryptedParts:     adminEncryptedParts,
		ProvidersEncryptedParts: providersEncryptedParts,
	}

	hash, err := walletBackup.HashForSigning()
	if err != nil {
		return nil, err
	}
	walletBackup.Signature, err = utils.Sign(hash[:], wallet.PrivateKey)
	if err != nil {
		return nil, err
	}

	return walletBackup, nil
}

func SplitAndEncrypt(key *ecdsa.PrivateKey, encryptionPubKeys []*ecdsa.PublicKey, threshold uint64,
	weights []uint16, backupId WalletBackupId, sigPrivKey *ecdsa.PrivateKey, isAdmin bool) (*EncryptedShares, error) {
	if len(encryptionPubKeys) != len(weights) {
		return nil, errors.New("number of encryption keys and weights do not match")
	}

	var numSplits = len(encryptionPubKeys)

	encryptionPubKeysApi := make([]types.ECDSAPublicKey, numSplits)
	for i, pubKey := range encryptionPubKeys {
		encryptionPubKeysApi[i] = types.PubKeyToStruct(pubKey)
	}
	encryptedShares := EncryptedShares{
		Splits:           make([][]byte, numSplits),
		OwnersPublicKeys: encryptionPubKeysApi,
		Threshold:        threshold,
		PublicKey:        types.PubKeyToStruct(&key.PublicKey),
		Weights:          make([]uint16, numSplits),
	}
	copy(encryptedShares.Weights, weights)

	numShares := uint64(utils.Sum(weights))
	shamirShares, err := utils.SplitToShamirShares(key.D, numShares, threshold)
	if err != nil {
		return nil, err
	}

	weightCounter := 0
	partialBackupId := PartialWalletBackupId{
		WalletBackupId: backupId, PartialPubKey: encryptedShares.PublicKey, IsAdmin: isAdmin,
	}
	for i := range numSplits {
		keySplitData := KeySplitData{
			Shares:                shamirShares[weightCounter : weightCounter+int(weights[i])],
			PartialWalletBackupId: partialBackupId,
			OwnerPublicKey:        types.PubKeyToStruct(encryptionPubKeys[i]),
		}
		sig, err := keySplitData.Sign(sigPrivKey)
		if err != nil {
			return nil, err
		}

		keySplit := KeySplit{KeySplitData: keySplitData, Signature: sig}

		plaintext, err := json.Marshal(keySplit)
		if err != nil {
			return nil, err
		}

		pubKey := ecies.ImportECDSAPublic(encryptionPubKeys[i])
		cipher, err := ecies.Encrypt(rand.Reader, pubKey, plaintext, nil, nil)
		if err != nil {
			return nil, err
		}

		encryptedShares.Splits[i] = cipher
		weightCounter = weightCounter + int(weights[i])
	}

	return &encryptedShares, nil
}

func GetPositionRole(walletBackup *WalletBackup, pubKeyECDSA types.ECDSAPublicKey) (int, int, error) {
	adminPos := -1
	for i, pubKey := range walletBackup.AdminEncryptedParts.OwnersPublicKeys {
		if pubKeyECDSA == pubKey {
			adminPos = i
			break
		}
	}

	provPos := -1
	for i, pubKey := range walletBackup.ProvidersEncryptedParts.OwnersPublicKeys {
		if pubKeyECDSA == pubKey {
			provPos = i
			break
		}
	}
	if adminPos == -1 && provPos == -1 {
		return adminPos, provPos, errors.New("no encrypted share for the given public key")
	}

	return adminPos, provPos, nil
}

func DecryptSplit(encryptedShare []byte, privKeyECDSA *ecdsa.PrivateKey) (*KeySplit, error) {
	privKeyDecryption := ecies.ImportECDSA(privKeyECDSA)
	shareBytes, err := privKeyDecryption.Decrypt(encryptedShare, nil, nil)
	if err != nil {
		return nil, err
	}

	var keySplit KeySplit
	err = json.Unmarshal(shareBytes, &keySplit)
	if err != nil {
		return nil, err
	}

	err = keySplit.VerifySignature()
	if err != nil {
		return nil, err
	}

	if keySplit.OwnerPublicKey != types.PubKeyToStruct(&privKeyECDSA.PublicKey) {
		return nil, errors.New("public key defined in the split does not match given public key")
	}

	return &keySplit, nil
}

func RecoverWallet(
	keyShares []*KeySplit,
	backupMetaData WalletBackupMetaData,
) (*Wallet, error) {
	providersKeyShares := make([]*KeySplit, 0)
	adminsKeyShares := make([]*KeySplit, 0)
	for _, keySplit := range keyShares {
		if keySplit.IsAdmin {
			adminsKeyShares = append(adminsKeyShares, keySplit)
		} else {
			providersKeyShares = append(providersKeyShares, keySplit)
		}
	}

	err := CheckKeyShares(adminsKeyShares, backupMetaData)
	if err != nil {
		return nil, err
	}
	adminsKey, err := JoinKeyShares(adminsKeyShares, backupMetaData.AdminsThreshold)
	if err != nil {
		return nil, err
	}

	err = CheckKeyShares(providersKeyShares, backupMetaData)
	if err != nil {
		return nil, err
	}
	providersKey, err := JoinKeyShares(providersKeyShares, backupMetaData.ProvidersThreshold)
	if err != nil {
		return nil, err
	}

	key, err := utils.JoinPrivateKeys([]*ecdsa.PrivateKey{adminsKey, providersKey})
	if err != nil {
		return nil, err
	}

	if types.PubKeyToStruct(&key.PublicKey) != backupMetaData.PublicKey {
		return nil, errors.New("private key reconstruction error: final result does not match address")
	}

	sec1PubKey := utils.SerializeCompressed(&key.PublicKey)
	xrpAddress, err := utils.GetXrpAddressFromPubkey(sec1PubKey)
	if err != nil {
		return nil, err
	}

	adminsPubKeys := make([]*ecdsa.PublicKey, len(backupMetaData.AdminsPublicKeys))
	for i, pubKey := range backupMetaData.AdminsPublicKeys {
		adminsPubKeys[i], err = types.ParsePubKey(pubKey)
		if err != nil {
			return nil, err
		}
	}

	return &Wallet{
		WalletId:   backupMetaData.WalletId,
		KeyId:      backupMetaData.KeyId,
		PrivateKey: key,
		Address:    crypto.PubkeyToAddress(key.PublicKey),
		XrpAddress: xrpAddress,
		Restored:   true,

		AdminsPublicKeys:   adminsPubKeys,
		AdminsThreshold:    backupMetaData.AdminsThreshold,
		Cosigners:          backupMetaData.Cosigners,
		CosignersThreshold: backupMetaData.CosignersThreshold,
		OpType:             backupMetaData.OpType,
		OpTypeConstants:    backupMetaData.OpTypeConstants,
	}, nil
}

func CheckKeyShares(splits []*KeySplit, backupMetaData WalletBackupMetaData) error {
	if len(splits) == 0 {
		return errors.New("shares should not be empty")
	}
	partialBackupId := splits[0].PartialWalletBackupId
	for _, split := range splits {
		if split.PartialWalletBackupId != partialBackupId {
			return errors.New("one of key split's ids does not match expected id")
		}

		if split.IsAdmin {
			if !slices.Contains(backupMetaData.AdminsPublicKeys, split.OwnerPublicKey) {
				return errors.New("one of admins public keys is not in the backup metadata")
			}
		}
	}

	if partialBackupId.WalletBackupId != backupMetaData.WalletBackupId {
		return errors.New("backup metadata's id does not match expected id")
	}

	return nil
}

// JoinKeyShares assumes that all the splits have the same backup id and the signatures have been verified.
func JoinKeyShares(splits []*KeySplit, threshold uint64) (*ecdsa.PrivateKey, error) {
	if threshold <= 0 {
		return nil, errors.New("threshold should be positive")
	}

	shares := make([]utils.ShamirShare, 0)
	for _, split := range splits {
		shares = append(shares, split.Shares...)
	}

	if uint64(len(shares)) < threshold {
		return nil, errors.New("threshold of shares is not reached")
	}
	shares = shares[:threshold]

	privateKeyBigInt, err := utils.CombineShamirShares(shares)
	if err != nil {
		return nil, err
	}
	privateKey := crypto.ToECDSAUnsafe(privateKeyBigInt.Bytes())
	expectedPartialPublicKey := splits[0].PartialPubKey // at this point splits is checked to not be empty
	if types.PubKeyToStruct(&privateKey.PublicKey) != expectedPartialPublicKey {
		return nil, err
	}

	return privateKey, nil
}
