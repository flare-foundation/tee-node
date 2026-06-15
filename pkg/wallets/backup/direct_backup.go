package backup

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/wallets"
)

// KeyDirectBackupPayload is the JSON-serializable form of a wallet
// produced by KEY_DIRECT_BACKUP. BackupID identifies the wallet+key
// and binds it to the source TEE, the reward epoch, and a per-backup
// random nonce. EncryptedPrivateKey is ECIES under the destination's
// public key; the remaining wallet-configuration fields are
// plaintext and are covered by the source TEE's signature over the
// payload.
type KeyDirectBackupPayload struct {
	BackupID wallets.WalletBackupID `json:"backupId"`

	// EncryptedPrivateKey is ECIES(destinationPub, w.PrivateKey).
	EncryptedPrivateKey hexutil.Bytes `json:"encryptedPrivateKey"`

	AdminPublicKeys    []types.PublicKey `json:"adminPublicKeys"`
	AdminsThreshold    uint64            `json:"adminsThreshold"`
	Cosigners          []common.Address  `json:"cosigners"`
	CosignersThreshold uint64            `json:"cosignersThreshold"`

	SettingsVersion common.Hash   `json:"settingsVersion"`
	Settings        hexutil.Bytes `json:"settings"`

	Status wallets.WalletStatus `json:"status"`
}

// NewKeyDirectBackupPayload assembles the wire-format direct-backup
// payload. The caller supplies encryptedPrivateKey (typically ECIES of
// w.PrivateKey under the destination's public key); the helper derives
// the secp256k1 public key for BackupID, copies slices defensively,
// and stamps the freshness markers. Only signing algorithms in
// wallets.Algos are supported.
func NewKeyDirectBackupPayload(
	w *wallets.Wallet,
	sourceTeeID common.Address,
	encryptedPrivateKey hexutil.Bytes,
	rewardEpochID uint32,
	randomNonce common.Hash,
) (*KeyDirectBackupPayload, error) {
	if w == nil {
		return nil, errors.New("wallet is nil")
	}
	if w.Status == nil {
		return nil, errors.New("wallet status is nil")
	}
	if !slices.Contains(wallets.Algos, w.SigningAlgo) {
		return nil, fmt.Errorf("unsupported signing algorithm: %s", w.SigningAlgo.Hex())
	}

	priv := wallets.ToECDSAUnsafe(w.PrivateKey)

	adminPubKeys := make([]types.PublicKey, len(w.AdminPublicKeys))
	for i, pk := range w.AdminPublicKeys {
		adminPubKeys[i] = types.PubKeyToStruct(pk)
	}

	cosigners := append([]common.Address(nil), w.Cosigners...)
	settings := append(hexutil.Bytes(nil), w.Settings...)
	encryptedCopy := append(hexutil.Bytes(nil), encryptedPrivateKey...)

	return &KeyDirectBackupPayload{
		BackupID: wallets.WalletBackupID{
			TeeID:         sourceTeeID,
			WalletID:      w.WalletID,
			KeyID:         w.KeyID,
			PublicKey:     types.PubKeyToBytes(&priv.PublicKey),
			KeyType:       w.KeyType,
			SigningAlgo:   w.SigningAlgo,
			RewardEpochID: rewardEpochID,
			RandomNonce:   randomNonce,
		},
		EncryptedPrivateKey: encryptedCopy,
		AdminPublicKeys:     adminPubKeys,
		AdminsThreshold:     w.AdminsThreshold,
		Cosigners:           cosigners,
		CosignersThreshold:  w.CosignersThreshold,
		SettingsVersion:     w.SettingsVersion,
		Settings:            settings,
		Status:              *w.Status,
	}, nil
}

// WalletFromKeyDirectBackupPayload reconstructs a wallets.Wallet from
// a direct-backup payload. The caller decrypts EncryptedPrivateKey
// out-of-band (typically with the destination TEE's ECIES key) and
// passes the plaintext private-key bytes in. The decrypted public key
// must match BackupID.PublicKey. The resulting wallet is marked
// Restored with a zero status.
func WalletFromKeyDirectBackupPayload(p *KeyDirectBackupPayload, privateKey []byte) (*wallets.Wallet, error) {
	if p == nil {
		return nil, errors.New("payload is nil")
	}
	if len(privateKey) == 0 {
		return nil, errors.New("private key is empty")
	}

	priv, err := crypto.ToECDSA(privateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid decrypted private key: %w", err)
	}
	derivedPub := types.PubKeyToBytes(&priv.PublicKey)
	if !slices.Equal(derivedPub, []byte(p.BackupID.PublicKey)) {
		return nil, errors.New("decrypted private key does not match BackupID.PublicKey")
	}

	adminPubKeys := make([]*ecdsa.PublicKey, len(p.AdminPublicKeys))
	for i, pk := range p.AdminPublicKeys {
		parsed, err := types.ParsePubKey(pk)
		if err != nil {
			return nil, err
		}
		adminPubKeys[i] = parsed
	}

	return &wallets.Wallet{
		WalletID:           p.BackupID.WalletID,
		KeyID:              p.BackupID.KeyID,
		PrivateKey:         append([]byte(nil), privateKey...),
		KeyType:            p.BackupID.KeyType,
		SigningAlgo:        p.BackupID.SigningAlgo,
		Restored:           true,
		AdminPublicKeys:    adminPubKeys,
		AdminsThreshold:    p.AdminsThreshold,
		Cosigners:          append([]common.Address(nil), p.Cosigners...),
		CosignersThreshold: p.CosignersThreshold,
		SettingsVersion:    p.SettingsVersion,
		Settings:           append(hexutil.Bytes(nil), p.Settings...),
		Status:             &wallets.WalletStatus{Nonce: 0, StatusCode: 0},
	}, nil
}
