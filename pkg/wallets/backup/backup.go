package backup

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"

	csigning "github.com/flare-foundation/go-flare-common/pkg/signing"
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

// SignHash returns the domain-separated, chain-bound preimage signed for a key
// split: signing.Payload{csigning.PMWKeySplit, chainID, HashForSigning()}.Hash().
func (ksd *KeySplitData) SignHash(chainID uint64) (common.Hash, error) {
	hash, err := ksd.HashForSigning()
	if err != nil {
		return common.Hash{}, err
	}
	return csigning.NewPayload(csigning.PMWKeySplit, chainID, hash).Hash()
}

// Sign signs the key split data with the provided private key.
func (ksd *KeySplitData) Sign(signer wallets.Signer, chainID uint64) ([]byte, error) {
	signHash, err := ksd.SignHash(chainID)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(signHash[:])
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// VerifySignature checks that the key split signature matches the owner key.
func (ks *KeySplit) VerifySignature(chainID uint64) error {
	signHash, err := ks.SignHash(chainID)
	if err != nil {
		return err
	}

	return wallets.VerifySignature(signHash[:], ks.Signature, ks.PublicKey, ks.SigningAlgo)
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

// OwnerSignHash returns the domain-separated, chain-bound preimage signed by
// the wallet (owner) key over the backup:
// signing.Payload{csigning.PMWWalletBackup, chainID, HashForSigning()}.Hash().
func (wb *WalletBackup) OwnerSignHash(chainID uint64) (common.Hash, error) {
	hash, err := wb.HashForSigning()
	if err != nil {
		return common.Hash{}, err
	}
	return csigning.NewPayload(csigning.PMWWalletBackup, chainID, hash).Hash()
}

// TEESignHash returns the domain-separated, chain-bound preimage signed by the
// TEE identity key over the backup:
// signing.Payload{csigning.TEEWalletBackup, chainID, HashForSigning()}.Hash().
func (wb *WalletBackup) TEESignHash(chainID uint64) (common.Hash, error) {
	hash, err := wb.HashForSigning()
	if err != nil {
		return common.Hash{}, err
	}
	return csigning.NewPayload(csigning.TEEWalletBackup, chainID, hash).Hash()
}

// Check validates the metadata and share alignment in the wallet backup.
func (wb *WalletBackup) Check(chainID uint64) error {
	if wb.AdminEncryptedParts == nil {
		return errors.New("admin encrypted parts not present not matching given data")
	}

	if wb.ProviderEncryptedParts == nil {
		return errors.New("provider encrypted parts not present not matching given data")
	}

	err := wb.AdminEncryptedParts.Check()
	if err != nil {
		return fmt.Errorf("admin parts check: %w", err)
	}
	err = wb.ProviderEncryptedParts.Check()
	if err != nil {
		return fmt.Errorf("provider parts check: %w", err)
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

	ownerSignHash, err := wb.OwnerSignHash(chainID)
	if err != nil {
		return err
	}
	if err = wallets.VerifySignature(ownerSignHash[:], wb.Signature, wb.PublicKey, wb.SigningAlgo); err != nil {
		return fmt.Errorf("wallet signature invalid: %w", err)
	}

	teeSignHash, err := wb.TEESignHash(chainID)
	if err != nil {
		return err
	}
	if err = utils.VerifySignature(teeSignHash[:], wb.TEESignature, wb.TeeID); err != nil {
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
	if utils.SumUint64(e.Weights) < e.Threshold {
		return errors.New("threshold too high")
	}

	return nil
}

// DecryptSplit decrypts an encrypted key split and verifies its integrity.
func DecryptSplit(encryptedShare []byte, privKeyECDSA *ecdsa.PrivateKey, chainID uint64) (*KeySplit, error) {
	shareBytes, err := utils.Decrypt(encryptedShare, privKeyECDSA)
	if err != nil {
		return nil, err
	}

	var keySplit KeySplit
	err = json.Unmarshal(shareBytes, &keySplit)
	if err != nil {
		return nil, err
	}

	err = keySplit.VerifySignature(chainID)
	if err != nil {
		return nil, err
	}

	if keySplit.OwnerPublicKey != types.PubKeyToStruct(&privKeyECDSA.PublicKey) {
		return nil, errors.New("public key defined in the split does not match given public key")
	}

	return &keySplit, nil
}
