package backup

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"math/big"

	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/tee"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

type WalletBackup struct {
	WalletBackupMetaData
	AdminEncryptedParts    *EncryptedShares
	ProviderEncryptedParts *EncryptedShares
	Signature              []byte
}

type WalletBackupMetaData struct {
	types.WalletBackupId
	OpTypeConstants []byte

	AdminsPublicKeys   []tee.PublicKey
	AdminsThreshold    uint64
	ProvidersThreshold uint64
	Cosigners          []common.Address
	CosignersThreshold uint64
}

type EncryptedShares struct {
	Splits           [][]byte
	OwnersPublicKeys []tee.PublicKey
	Threshold        uint64
	PublicKey        tee.PublicKey
	Weights          []uint16
}

type ShamirShare struct {
	X *big.Int
	Y *big.Int
}

func (s *ShamirShare) ID() string {
	return s.X.String()
}

type KeySplit struct {
	KeySplitData
	Signature []byte
}

type KeySplitData struct {
	Shares []ShamirShare
	PartialWalletBackupId
	OwnerPublicKey tee.PublicKey
}

type PartialWalletBackupId struct {
	types.WalletBackupId
	PartialPubKey tee.PublicKey
	IsAdmin       bool
}

func (ksd *KeySplitData) HashForSigning() (common.Hash, error) {
	keyDataBytes, err := json.Marshal(ksd)
	if err != nil {
		return common.Hash{}, err
	}
	hash := crypto.Keccak256Hash(keyDataBytes)

	return hash, nil
}

func (ksd *KeySplitData) Sign(privKey *ecdsa.PrivateKey) ([]byte, error) {
	hash, err := ksd.HashForSigning()
	if err != nil {
		return nil, err
	}

	signature, err := utils.Sign(hash[:], privKey)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (ks *KeySplit) VerifySignature() error {
	hash, err := ks.HashForSigning()
	if err != nil {
		return err
	}

	pubKeyParsed, err := types.ParsePubKey(ks.PublicKey)
	if err != nil {
		return err
	}
	mainKeyAddress := crypto.PubkeyToAddress(*pubKeyParsed)

	err = utils.VerifySignature(hash[:], ks.Signature, mainKeyAddress)

	return err
}

func (wb *WalletBackup) HashForSigning() (common.Hash, error) {
	type WalletBackupForHashing struct {
		WalletBackupMetaData
		AdminEncryptedParts    *EncryptedShares
		ProviderEncryptedParts *EncryptedShares
	}

	walletBackupBytes, err := json.Marshal(WalletBackupForHashing{
		WalletBackupMetaData:   wb.WalletBackupMetaData,
		AdminEncryptedParts:    wb.AdminEncryptedParts,
		ProviderEncryptedParts: wb.ProviderEncryptedParts,
	})
	if err != nil {
		return common.Hash{}, err
	}
	hash := crypto.Keccak256Hash(walletBackupBytes)

	return hash, nil
}

func (wb *WalletBackup) Check() error {
	err := wb.AdminEncryptedParts.Check()
	if err != nil {
		return err
	}
	err = wb.ProviderEncryptedParts.Check()
	if err != nil {
		return err
	}

	if wb.AdminsThreshold != wb.AdminEncryptedParts.Threshold {
		return errors.New("admin threshold not matching given data")
	}

	if wb.ProvidersThreshold != wb.ProviderEncryptedParts.Threshold {
		return errors.New("providers threshold not matching given data")
	}

	if len(wb.AdminsPublicKeys) != len(wb.AdminEncryptedParts.OwnersPublicKeys) {
		return errors.New("length of admin public keys not matching given data")
	}

	for i, pubKey := range wb.AdminsPublicKeys {
		if pubKey != wb.AdminEncryptedParts.OwnersPublicKeys[i] {
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
