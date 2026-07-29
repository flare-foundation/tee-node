package backup

import (
	"crypto/ecdsa"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/wallets"
)

// payloadFor builds a KeyDirectBackupPayload whose BackupID.PublicKey is
// the secp256k1 public key derived from priv.
func payloadFor(t *testing.T, priv *ecdsa.PrivateKey) *KeyDirectBackupPayload {
	t.Helper()

	pubBytes := types.PubKeyToBytes(&priv.PublicKey)
	return &KeyDirectBackupPayload{
		BackupID: wallets.WalletBackupID{
			TeeID:         common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			WalletID:      common.HexToHash("0xabcdef"),
			KeyID:         1,
			PublicKey:     hexutil.Bytes(pubBytes),
			KeyType:       wallets.EVMType,
			SigningAlgo:   wallets.EVMSignAlgo,
			RewardEpochID: 1,
			RandomNonce:   common.HexToHash("0xbeef"),
		},
		Status: wallets.WalletStatus{},
	}
}

func TestWalletFromKeyDirectBackupPayloadMatchingKey(t *testing.T) {
	priv, err := crypto.GenerateKey()
	require.NoError(t, err)

	payload := payloadFor(t, priv)
	w, err := WalletFromKeyDirectBackupPayload(payload, common.BigToHash(priv.D).Bytes())
	require.NoError(t, err)
	require.True(t, w.Restored)
	require.Equal(t, payload.BackupID.WalletID, w.WalletID)
	require.Equal(t, payload.BackupID.KeyID, w.KeyID)
}

func TestWalletFromKeyDirectBackupPayloadMismatchedPublicKey(t *testing.T) {
	realPriv, err := crypto.GenerateKey()
	require.NoError(t, err)
	imposterPriv, err := crypto.GenerateKey()
	require.NoError(t, err)

	payload := payloadFor(t, imposterPriv)

	_, err = WalletFromKeyDirectBackupPayload(payload, common.BigToHash(realPriv.D).Bytes())
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match BackupID.PublicKey")
}

func TestWalletFromKeyDirectBackupPayloadEmptyPublicKey(t *testing.T) {
	priv, err := crypto.GenerateKey()
	require.NoError(t, err)

	payload := payloadFor(t, priv)
	payload.BackupID.PublicKey = nil

	_, err = WalletFromKeyDirectBackupPayload(payload, common.BigToHash(priv.D).Bytes())
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match BackupID.PublicKey")
}
