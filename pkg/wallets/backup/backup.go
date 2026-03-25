package backup

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
	"github.com/flare-foundation/tee-node/pkg/wallets"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

type WalletBackup struct {
	WalletBackupMetaData
	AdminEncryptedParts    *EncryptedShares
	ProviderEncryptedParts *EncryptedShares
	Signature              hexutil.Bytes
	TEESignature           hexutil.Bytes
}

type WalletBackupMetaData struct {
	wallets.WalletBackupID

	AdminsPublicKeys   []types.PublicKey
	AdminsThreshold    uint64
	ProvidersThreshold uint64
	Cosigners          []common.Address
	CosignersThreshold uint64
}

type EncryptedShares struct {
	Splits           []hexutil.Bytes
	OwnersPublicKeys []types.PublicKey
	Threshold        uint64
	PublicKey        hexutil.Bytes
	Weights          []uint16
}

type ShamirShare struct {
	X *big.Int
	Y *big.Int
}

// ID returns the string identifier for the Shamir share.
func (s *ShamirShare) ID() string {
	return s.X.String()
}

type KeySplit struct {
	KeySplitData
	Signature []byte
}

type KeySplitData struct {
	Shares []ShamirShare
	PartialWalletBackupID
	OwnerPublicKey types.PublicKey
}

type PartialWalletBackupID struct {
	wallets.WalletBackupID
	PartialPubKey hexutil.Bytes
	IsAdmin       bool
}

func (pwid *PartialWalletBackupID) Equal(w *PartialWalletBackupID) bool {
	return pwid.WalletBackupID.Equal(&w.WalletBackupID) == nil &&
		slices.Compare(pwid.PartialPubKey, w.PartialPubKey) == 0 &&
		pwid.IsAdmin == w.IsAdmin
}

// HashForSigning computes the hash used when signing the key split data.
func (ksd *KeySplitData) HashForSigning() (common.Hash, error) {
	keyDataBytes, err := json.Marshal(ksd)
	if err != nil {
		return common.Hash{}, err
	}
	hash := crypto.Keccak256Hash(keyDataBytes)

	return hash, nil
}

// Sign signs the key split data with the provided private key.
func (ksd *KeySplitData) Sign(signer wallets.Signer) ([]byte, error) {
	hash, err := ksd.HashForSigning()
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(PadForSigning(hash))
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// VerifySignature checks that the key split signature matches the owner key.
func (ks *KeySplit) VerifySignature() error {
	hash, err := ks.HashForSigning()
	if err != nil {
		return err
	}

	return wallets.VerifySignature(PadForSigning(hash), ks.Signature, ks.PublicKey, ks.SigningAlgo)
}

// HashForSigning produces the hash over the wallet backup content.
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

// Check validates the metadata and share alignment in the wallet backup.
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

	hash, err := wb.HashForSigning()
	if err != nil {
		return err
	}

	if err = wallets.VerifySignature(PadForSigning(hash), wb.Signature, wb.PublicKey, wb.SigningAlgo); err != nil {
		return fmt.Errorf("wallet signature invalid: %w", err)
	}

	if err = utils.VerifySignature(hash[:], wb.TEESignature, wb.TeeID); err != nil {
		return fmt.Errorf("TEE signature invalid: %w", err)
	}

	return nil
}

// Check ensures the encrypted shares meet threshold and weighting
// requirements.
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

// DecryptSplit decrypts an encrypted key split and verifies its integrity.
func DecryptSplit(encryptedShare []byte, privKeyECDSA *ecdsa.PrivateKey) (*KeySplit, error) {
	privKeyDecryption, err := utils.ECDSAPrivKeyToECIES(privKeyECDSA)
	if err != nil {
		return nil, err
	}
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

func PadForSigning(hash common.Hash) []byte {
	return fmt.Appendf(nil, "\x19Flare PMW backup:\n%d%s", len(hash), hash)
}
