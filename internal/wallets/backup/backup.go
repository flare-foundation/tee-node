package backup

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"slices"

	"github.com/flare-foundation/go-flare-common/pkg/random"
	"github.com/flare-foundation/tee-node/pkg/wallets"
	"github.com/flare-foundation/tee-node/pkg/wallets/backup"

	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

const NormalizationConstant = 1000
const DataProvidersThreshold = uint64(666)

// BackupWallet packages the wallet state and encrypted key shares for admins
// and providers so it can be reconstructed later. The result is signed with the
// key that is split, but remains to be signed by the TEE.
func BackupWallet(wallet *wallets.Wallet, providerPubKeys []*ecdsa.PublicKey, signingPolicyWeights []uint16, rewardEpochID uint32, teeID common.Address, chainID uint64, normalizationParam uint16, dataProviderThreshold uint64) (*backup.WalletBackup, error) {
	switch wallet.SigningAlgo {
	case wallets.XRPSignAlgo, wallets.EVMSignAlgo, wallets.VRFAlgo:
		// continue
	default:
		return nil, errors.New("unsupported signing algorithm")
	}

	field, err := backup.FieldFor(wallet.KeyType, wallet.SigningAlgo)
	if err != nil {
		return nil, err
	}

	adminPubKeys := make([]types.PublicKey, len(wallet.AdminPublicKeys))
	for i, pubKey := range wallet.AdminPublicKeys {
		adminPubKeys[i] = types.PubKeyToStruct(pubKey)
	}
	normalizedWeights, err := weightsNormalization(signingPolicyWeights, normalizationParam)
	if err != nil {
		return nil, err
	}
	randomNonce, err := random.Hash()
	if err != nil {
		return nil, err
	}

	walletPubKey, err := wallet.PubKey()
	if err != nil {
		return nil, err
	}

	metaData := backup.WalletBackupMetaData{
		WalletBackupID: wallets.WalletBackupID{
			TeeID:         teeID,
			WalletID:      wallet.WalletID,
			KeyID:         wallet.KeyID,
			PublicKey:     walletPubKey,
			KeyType:       wallet.KeyType,
			SigningAlgo:   wallet.SigningAlgo,
			RewardEpochID: rewardEpochID,
			RandomNonce:   randomNonce,
		},
		FieldID:            field.ID,
		AdminsPublicKeys:   adminPubKeys,
		AdminsThreshold:    wallet.AdminsThreshold,
		ProvidersThreshold: dataProviderThreshold,
		Cosigners:          make([]common.Address, len(wallet.Cosigners)),
		CosignersThreshold: wallet.CosignersThreshold,
	}
	copy(metaData.Cosigners, wallet.Cosigners)

	splitKey, err := SplitSecret(field, wallet.PrivateKey, 2)
	if err != nil {
		return nil, err
	}

	weightsOne := utils.ConstantSlice(uint16(1), len(wallet.AdminPublicKeys))
	adminEncryptedParts, err := SplitAndEncrypt(field, splitKey[0], wallet.AdminPublicKeys, wallet.AdminsThreshold, weightsOne, metaData.WalletBackupID, wallet, true, chainID)
	if err != nil {
		return nil, err
	}

	providerEncryptedParts, err := SplitAndEncrypt(field, splitKey[1], providerPubKeys, dataProviderThreshold, normalizedWeights, metaData.WalletBackupID, wallet, false, chainID)
	if err != nil {
		return nil, err
	}

	walletBackup := &backup.WalletBackup{
		WalletBackupMetaData:   metaData,
		AdminEncryptedParts:    adminEncryptedParts,
		ProviderEncryptedParts: providerEncryptedParts,
	}

	ownerSignHash, err := walletBackup.OwnerSignHash(chainID)
	if err != nil {
		return nil, err
	}
	walletBackup.Signature, err = wallet.Sign(ownerSignHash[:])
	if err != nil {
		return nil, err
	}

	return walletBackup, nil
}

func weightsNormalization(weights []uint16, total uint16) ([]uint16, error) {
	sum := uint16(0)
	for _, weight := range weights {
		if weight == 0 {
			continue
		}
		if sum >= -weight {
			return nil, errors.New("overflow of weights")
		}
		sum += weight
	}

	if sum == 0 {
		// this should not happen
		return nil, errors.New("total weight is zero")
	}

	normalizedWeights := make([]uint16, len(weights))

	for i, weight := range weights {
		if sum == 0 {
			// in case the last few weights are zero, we just let the rest of normalized weights be zero to avoid division by zero
			break
		}
		normalizedWeight := uint16((uint64(weight) * uint64(total) / uint64(sum)))
		sum -= weight
		total -= normalizedWeight
		normalizedWeights[i] = normalizedWeight
	}

	return normalizedWeights, nil
}

// SplitAndEncrypt shards the provided secret over the given field, encrypts
// each share for its owner, and returns the encoded share bundle.
func SplitAndEncrypt(
	field *backup.Field,
	secret []byte,
	encryptionPubKeys []*ecdsa.PublicKey,
	threshold uint64,
	weights []uint16,
	backupID wallets.WalletBackupID,
	signer wallets.Signer,
	isAdmin bool,
	chainID uint64,
) (*backup.EncryptedShares, error) {
	if len(encryptionPubKeys) != len(weights) {
		return nil, errors.New("number of encryption keys and weights do not match")
	}

	var numSplits = len(encryptionPubKeys)

	encryptionPubKeysApi := make([]types.PublicKey, numSplits)
	for i, pubKey := range encryptionPubKeys {
		encryptionPubKeysApi[i] = types.PubKeyToStruct(pubKey)
	}
	encryptedShares := backup.EncryptedShares{
		Splits:           make([]hexutil.Bytes, numSplits),
		OwnersPublicKeys: encryptionPubKeysApi,
		Threshold:        threshold,
		Weights:          make([]uint16, numSplits),
	}
	copy(encryptedShares.Weights, weights)

	numShares := utils.SumUint64(weights)
	shamirShares, err := SplitToShamirShares(field, secret, numShares, threshold)
	if err != nil {
		return nil, err
	}

	weightCounter := 0
	partialBackupID := backup.PartialWalletBackupID{
		WalletBackupID: backupID, IsAdmin: isAdmin,
	}
	for i := range numSplits {
		keySplitData := backup.KeySplitData{
			Shares:                shamirShares[weightCounter : weightCounter+int(weights[i])],
			PartialWalletBackupID: partialBackupID,
			OwnerPublicKey:        types.PubKeyToStruct(encryptionPubKeys[i]),
		}
		sig, err := keySplitData.Sign(signer, chainID)
		if err != nil {
			return nil, err
		}

		keySplit := backup.KeySplit{KeySplitData: keySplitData, Signature: sig}

		plaintext, err := json.Marshal(keySplit)
		if err != nil {
			return nil, err
		}

		cipher, err := utils.Encrypt(plaintext, encryptionPubKeys[i])
		if err != nil {
			return nil, err
		}

		encryptedShares.Splits[i] = cipher
		weightCounter += int(weights[i])
	}

	return &encryptedShares, nil
}

// RecoverWallet rebuilds a wallet from key shares and backup metadata.
func RecoverWallet(
	keyShares []*backup.KeySplit,
	backupMetaData *backup.WalletBackupMetaData,
) (*wallets.Wallet, error) {
	providerKeyShares := make([]*backup.KeySplit, 0)
	adminKeyShares := make([]*backup.KeySplit, 0)
	for _, keySplit := range keyShares {
		if keySplit.IsAdmin {
			adminKeyShares = append(adminKeyShares, keySplit)
		} else {
			providerKeyShares = append(providerKeyShares, keySplit)
		}
	}

	// The field is taken from the backup rather than re-derived from the key
	// metadata, so a backup remains readable independently of the current
	// mapping from signing algorithm to field.
	field, err := backup.FieldForID(backupMetaData.FieldID)
	if err != nil {
		return nil, err
	}

	err = CheckKeyShares(adminKeyShares, backupMetaData)
	if err != nil {
		return nil, err
	}
	adminKey, err := JoinKeyShares(field, adminKeyShares, backupMetaData.AdminsThreshold)
	if err != nil {
		return nil, err
	}

	err = CheckKeyShares(providerKeyShares, backupMetaData)
	if err != nil {
		return nil, err
	}
	providerKey, err := JoinKeyShares(field, providerKeyShares, backupMetaData.ProvidersThreshold)
	if err != nil {
		return nil, err
	}

	secret, err := JoinSecret(field, adminKey, providerKey)
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

	recovered := &wallets.Wallet{
		WalletID:    backupMetaData.WalletID,
		KeyID:       backupMetaData.KeyID,
		PrivateKey:  secret,
		KeyType:     backupMetaData.KeyType,
		SigningAlgo: backupMetaData.SigningAlgo,
		Restored:    true,

		AdminPublicKeys:    adminsPubKeys,
		AdminsThreshold:    backupMetaData.AdminsThreshold,
		Cosigners:          backupMetaData.Cosigners,
		CosignersThreshold: backupMetaData.CosignersThreshold,

		SettingsVersion: common.Hash{},
		Settings:        hexutil.Bytes{},

		// StatusCode and PausingNonce are reset to zero on restore. This is
		// currently acceptable because neither field is used yet. Once they carry
		// security-relevant semantics (e.g. pausing restrictions), the backup
		// metadata must preserve and restore them, or Store() must re-apply them
		// from permanent storage.
		Status: &wallets.WalletStatus{Nonce: 0, StatusCode: 0},
	}

	// Deriving the public key through the wallet keeps the check tied to the
	// signing algorithm rather than assuming the secret is a curve scalar.
	recoveredPubKey, err := recovered.PubKey()
	if err != nil {
		return nil, err
	}
	if slices.Compare(recoveredPubKey, backupMetaData.PublicKey) != 0 {
		return nil, errors.New("private key reconstruction error: final result does not match address")
	}

	return recovered, nil
}

// CheckKeyShares validates that the provided key shares belong to the expected
// wallet backup metadata and originate from authorized parties.
func CheckKeyShares(splits []*backup.KeySplit, backupMetaData *backup.WalletBackupMetaData) error {
	if len(splits) == 0 {
		return errors.New("shares should not be empty")
	}
	partialBackupID := splits[0].PartialWalletBackupID
	for _, split := range splits {
		if !split.PartialWalletBackupID.Equal(&partialBackupID) { //nolint:staticcheck // to avoid confusion we do not call split.Equal
			return errors.New("one of key split's ids does not match expected id")
		}

		if split.IsAdmin {
			if !slices.Contains(backupMetaData.AdminsPublicKeys, split.OwnerPublicKey) {
				return errors.New("one of admins public keys is not in the backup metadata")
			}
		}
	}

	if err := partialBackupID.WalletBackupID.Equal(&backupMetaData.WalletBackupID); err != nil {
		return err
	}

	return nil
}

// JoinKeyShares joins key shares in a private key. It assumes that all the
// splits have the same backup id and the signatures have been verified.
func JoinKeyShares(field *backup.Field, splits []*backup.KeySplit, threshold uint64) ([]byte, error) {
	if threshold == 0 {
		return nil, errors.New("threshold should be positive")
	}

	// we do not pre-locate the slice to avoid possible OOM attacks
	shares := make([]backup.ShamirShare, 0)
	for _, split := range splits {
		shares = append(shares, split.Shares...)
	}

	if uint64(len(shares)) < threshold {
		return nil, errors.New("threshold of shares is not reached")
	}
	shares = shares[:threshold]

	// The reconstructed part carries no commitment of its own; a wrong
	// reconstruction is caught once the parts are combined, by comparing the
	// assembled key against the public key in the backup metadata. Individual
	// shares are authenticated by the wallet-key signature on each KeySplitData,
	// so a share that does not belong to this part is rejected before it
	// reaches interpolation.
	return CombineShamirShares(field, shares)
}
