package wallets

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestWallet(t *testing.T) {
	adminPrivateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	adminPubKey := types.PubKeyToStruct(&adminPrivateKey.PublicKey)
	adminPubKeys := []wallet.PublicKey{
		{
			X: adminPubKey.X,
			Y: adminPubKey.Y,
		},
	}

	teeID := common.HexToAddress("0xdead")

	kg := wallet.ITeeWalletKeyManagerKeyGenerate{
		TeeId:       teeID,
		KeyId:       1,
		WalletId:    common.HexToHash("0x01"),
		KeyType:     XRPType,
		SigningAlgo: XRPAlgo,
		ConfigConstants: wallet.ITeeWalletKeyManagerKeyConfigConstants{
			AdminsPublicKeys:   adminPubKeys,
			AdminsThreshold:    1,
			Cosigners:          []common.Address{},
			CosignersThreshold: 0,
		},
	}

	w, err := GenerateNewKey(kg)
	require.NoError(t, err)

	require.Equal(t, common.Hash(kg.WalletId), w.WalletID)
	require.Equal(t, kg.KeyId, w.KeyID)
	require.Equal(t, common.Hash(kg.KeyType), w.KeyType)
	require.Equal(t, common.Hash(kg.SigningAlgo), w.SigningAlgo)
	require.Equal(t, kg.ConfigConstants.AdminsThreshold, w.AdminsThreshold)
	require.Equal(t, kg.ConfigConstants.CosignersThreshold, w.CosignersThreshold)
	require.False(t, w.Restored)

	t.Run("key existence proof", func(t *testing.T) {
		proof := w.KeyExistenceProof(teeID)
		require.NotNil(t, proof)
		require.Equal(t, kg.WalletId, proof.WalletId)
		require.Equal(t, kg.KeyId, proof.KeyId)
		require.Equal(t, kg.KeyType, proof.KeyType)

		// Verify the public key matches the wallet's private key
		privateKey := ToECDSAUnsafe(w.PrivateKey)
		expectedPubKey := types.PubKeyToBytes(&privateKey.PublicKey)
		require.Equal(t, expectedPubKey, proof.PublicKey)
	})

	t.Run("decrypt", func(t *testing.T) {
		// Test message to encrypt
		message := []byte("test message for decryption")

		// Get the public key for encryption
		privateKey := ToECDSAUnsafe(w.PrivateKey)
		publicKey := &privateKey.PublicKey

		// Encrypt the message using ECIES
		pubKeyECIES, err := utils.ECDSAPubKeyToECIES(publicKey)
		require.NoError(t, err)
		ciphertext, err := ecies.Encrypt(rand.Reader, pubKeyECIES, message, nil, nil)
		require.NoError(t, err)

		// Decrypt the message using the wallet's Decrypt method
		decrypted, err := w.Decrypt(ciphertext)
		require.NoError(t, err)

		// Verify the decrypted message matches the original
		require.Equal(t, message, decrypted)
	})
}

func TestBackupID(t *testing.T) {
	prv, err := crypto.GenerateKey()
	require.NoError(t, err)

	zeroBI := WalletBackupID{
		TeeID:         common.Address{},
		WalletID:      common.Hash{},
		KeyID:         0,
		PublicKey:     hexutil.Bytes{},
		KeyType:       common.Hash{},
		SigningAlgo:   common.Hash{},
		RewardEpochID: 0,
		RandomNonce:   common.Hash{},
	}

	bI0 := WalletBackupID{
		TeeID:         common.HexToAddress("0x0000000000000000000000000000000000000001"),
		WalletID:      common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"),
		KeyID:         0,
		PublicKey:     types.PubKeyToBytes(&prv.PublicKey),
		KeyType:       XRPType,
		SigningAlgo:   XRPAlgo,
		RewardEpochID: 0,
		RandomNonce:   common.HexToHash("0x1000000000000000000000000000000000000000000000000000000000000001"),
	}

	bI1 := WalletBackupID{
		TeeID:         common.HexToAddress("0x0000000000000000000000000000000000000001"),
		WalletID:      common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"),
		KeyID:         0,
		PublicKey:     types.PubKeyToBytes(&prv.PublicKey),
		KeyType:       XRPType,
		SigningAlgo:   XRPAlgo,
		RewardEpochID: 0,
		RandomNonce:   common.HexToHash("0x1000000000000000000000000000000000000000000000000000000000000001"),
	}

	require.True(t, bI0.Equal(&bI1))

	t.Run("not equal", func(t *testing.T) {
		bI2 := WalletBackupID{
			TeeID:         common.Address{},
			WalletID:      common.Hash{},
			KeyID:         0,
			PublicKey:     hexutil.Bytes{},
			KeyType:       common.Hash{},
			SigningAlgo:   common.Hash{},
			RewardEpochID: 0,
			RandomNonce:   common.Hash{},
		}

		bI2.TeeID = bI0.TeeID
		require.False(t, bI0.Equal(&bI2))
		bI2.TeeID = zeroBI.TeeID

		bI2.WalletID = bI0.WalletID
		require.False(t, bI0.Equal(&bI2))
		bI2.WalletID = zeroBI.WalletID

		bI2.KeyID = bI0.KeyID
		require.False(t, bI0.Equal(&bI2))
		bI2.KeyID = zeroBI.KeyID

		bI2.PublicKey = bI0.PublicKey
		require.False(t, bI0.Equal(&bI2))
		bI2.PublicKey = zeroBI.PublicKey

		bI2.KeyType = bI0.KeyType
		require.False(t, bI0.Equal(&bI2))
		bI2.KeyType = zeroBI.KeyType

		bI2.SigningAlgo = bI0.SigningAlgo
		require.False(t, bI0.Equal(&bI2))
		bI2.SigningAlgo = zeroBI.SigningAlgo

		bI2.RewardEpochID = bI0.RewardEpochID
		require.False(t, bI0.Equal(&bI2))
		bI2.RewardEpochID = zeroBI.RewardEpochID

		bI2.RandomNonce = bI0.RandomNonce
		require.False(t, bI0.Equal(&bI2))
		bI2.RandomNonce = zeroBI.RandomNonce
	})

	t.Run("encoding + hash", func(t *testing.T) {
		h0 := zeroBI.Hash()
		require.NoError(t, err)

		h1 := bI0.Hash()
		require.NoError(t, err)

		require.NotEqual(t, h0, h1)
	})
}

func TestNonceCheck(t *testing.T) {
	err := nonceCheck(nil)
	require.Error(t, err)

	err = nonceCheck(big.NewInt(0).Lsh(big.NewInt(1), 257))
	require.Error(t, err)

	// err = nonceCheck(big.NewInt(-1))
	// require.Error(t, err)

	err = nonceCheck(big.NewInt(12345))
	require.NoError(t, err)
}
