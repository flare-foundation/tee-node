package wallets

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/stretchr/testify/require"
)

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
		_, err := bI0.prepareForEncoding()
		require.NoError(t, err)

		_, err = zeroBI.prepareForEncoding()
		require.NoError(t, err)

		h0 := zeroBI.Hash()
		h1 := bI0.Hash()
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
