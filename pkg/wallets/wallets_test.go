package wallets

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
	"github.com/stretchr/testify/require"
)

func generateAdminKeyPair(t *testing.T) (*ecdsa.PrivateKey, []wallet.PublicKey) {
	t.Helper()

	adminPrivateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	adminPubKey := types.PubKeyToStruct(&adminPrivateKey.PublicKey)
	adminPubKeys := []wallet.PublicKey{
		{
			X: adminPubKey.X,
			Y: adminPubKey.Y,
		},
	}

	return adminPrivateKey, adminPubKeys
}

func createKeyGenerateRequest(teeID common.Address, walletID common.Hash, keyID uint64, keyType, signingAlgo common.Hash, adminPubKeys []wallet.PublicKey, cosigners []common.Address) wallet.ITeeWalletKeyManagerKeyGenerate {
	return wallet.ITeeWalletKeyManagerKeyGenerate{
		TeeId:       teeID,
		KeyId:       keyID,
		WalletId:    walletID,
		KeyType:     keyType,
		SigningAlgo: signingAlgo,
		ConfigConstants: wallet.ITeeWalletKeyManagerKeyConfigConstants{
			AdminsPublicKeys:   adminPubKeys,
			AdminsThreshold:    1,
			Cosigners:          cosigners,
			CosignersThreshold: uint64(len(cosigners)),
		},
	}
}

func createTestWallet(t *testing.T, kg wallet.ITeeWalletKeyManagerKeyGenerate) *Wallet {
	t.Helper()

	w, err := GenerateNewKey(kg)
	require.NoError(t, err)

	require.Equal(t, common.Hash(kg.WalletId), w.WalletID)
	require.Equal(t, kg.KeyId, w.KeyID)
	require.Equal(t, common.Hash(kg.KeyType), w.KeyType)
	require.Equal(t, common.Hash(kg.SigningAlgo), w.SigningAlgo)
	require.Equal(t, kg.ConfigConstants.AdminsThreshold, w.AdminsThreshold)
	require.Equal(t, kg.ConfigConstants.CosignersThreshold, w.CosignersThreshold)
	require.False(t, w.Restored)

	return w
}

func TestWallet(t *testing.T) {
	_, adminPubKeys := generateAdminKeyPair(t)
	teeID := common.HexToAddress("0xdead")

	kg := createKeyGenerateRequest(
		teeID,
		common.HexToHash("0x01"),
		1,
		XRPType,
		XRPAlgo,
		adminPubKeys,
		[]common.Address{},
	)

	w := createTestWallet(t, kg)

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

	require.Nil(t, bI0.Equal(&bI1))

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
		require.NotNil(t, bI0.Equal(&bI2))
		bI2.TeeID = zeroBI.TeeID

		bI2.WalletID = bI0.WalletID
		require.NotNil(t, bI0.Equal(&bI2))
		bI2.WalletID = zeroBI.WalletID

		bI2.KeyID = bI0.KeyID
		require.NotNil(t, bI0.Equal(&bI2))
		bI2.KeyID = zeroBI.KeyID

		bI2.PublicKey = bI0.PublicKey
		require.NotNil(t, bI0.Equal(&bI2))
		bI2.PublicKey = zeroBI.PublicKey

		bI2.KeyType = bI0.KeyType
		require.NotNil(t, bI0.Equal(&bI2))
		bI2.KeyType = zeroBI.KeyType

		bI2.SigningAlgo = bI0.SigningAlgo
		require.NotNil(t, bI0.Equal(&bI2))
		bI2.SigningAlgo = zeroBI.SigningAlgo

		bI2.RewardEpochID = bI0.RewardEpochID
		require.NotNil(t, bI0.Equal(&bI2))
		bI2.RewardEpochID = zeroBI.RewardEpochID

		bI2.RandomNonce = bI0.RandomNonce
		require.NotNil(t, bI0.Equal(&bI2))
		bI2.RandomNonce = zeroBI.RandomNonce
	})

	t.Run("encoding + hash", func(t *testing.T) {
		h0, err := zeroBI.Hash()
		require.NoError(t, err)

		h1, err := bI0.Hash()
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

func TestWalletCopy(t *testing.T) {
	adminPrivateKey, _ := generateAdminKeyPair(t)
	adminPubKeys := []*ecdsa.PublicKey{&adminPrivateKey.PublicKey}

	w := &Wallet{
		WalletID:    common.HexToHash("0x01"),
		KeyID:       42,
		PrivateKey:  []byte{0x12, 0x34, 0x56},
		KeyType:     common.HexToHash("0x1111"),
		SigningAlgo: common.HexToHash("0xabcd"),

		Restored:           true,
		AdminPublicKeys:    adminPubKeys,
		AdminsThreshold:    1,
		Cosigners:          []common.Address{common.HexToAddress("0x1234567890123456789012345678901234567890")},
		CosignersThreshold: 3,
		SettingsVersion:    common.HexToHash("0xABCDEF"),
		Settings:           hexutil.Bytes{0xde, 0xad, 0xbe, 0xef},

		Status: &WalletStatus{
			Nonce:        123,
			StatusCode:   5,
			PausingNonce: common.HexToHash("0xDEAD"),
		},
	}

	cw := w.Copy()
	require.NotSame(t, w, cw)
	require.Equal(t, w.WalletID, cw.WalletID)
	require.Equal(t, w.KeyID, cw.KeyID)
	require.Equal(t, w.PrivateKey, cw.PrivateKey)
	require.Equal(t, w.KeyType, cw.KeyType)
	require.Equal(t, w.SigningAlgo, cw.SigningAlgo)
	require.Equal(t, w.Restored, cw.Restored)
	require.Equal(t, w.AdminsThreshold, cw.AdminsThreshold)
	require.Equal(t, w.CosignersThreshold, cw.CosignersThreshold)
	require.Equal(t, w.SettingsVersion, cw.SettingsVersion)
	require.Equal(t, w.Settings, cw.Settings)

	require.NotSame(t, &w.Settings, &cw.Settings)
	require.NotSame(t, &w.AdminPublicKeys, &cw.AdminPublicKeys)
	require.NotSame(t, &w.Cosigners, &cw.Cosigners)

	require.NotSame(t, w.Status, cw.Status)
	require.Equal(t, w.Status.Nonce, cw.Status.Nonce)
	require.Equal(t, w.Status.StatusCode, cw.Status.StatusCode)
	require.Equal(t, w.Status.PausingNonce, cw.Status.PausingNonce)

	require.Len(t, cw.AdminPublicKeys, len(w.AdminPublicKeys))
	require.Equal(t, w.AdminPublicKeys, cw.AdminPublicKeys)
	require.Equal(t, w.Cosigners, cw.Cosigners)
}

func TestCheckKeyGenerate(t *testing.T) {
	teeID := common.HexToAddress("0x0123456789abcdef0123456789abcdef01234567")
	adminPubKey := wallet.PublicKey{
		X: [32]byte{1},
		Y: [32]byte{2},
	}

	baseReq := createKeyGenerateRequest(
		teeID,
		common.HexToHash("0x11"),
		42,
		EVMType,
		EVMAlgo,
		[]wallet.PublicKey{adminPubKey},
		[]common.Address{common.HexToAddress("0x1")},
	)

	t.Run("ok", func(t *testing.T) {
		err := CheckKeyGenerate(baseReq, teeID)
		require.NoError(t, err)
	})

	t.Run("teeID mismatch", func(t *testing.T) {
		req := baseReq
		req.TeeId = common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
		err := CheckKeyGenerate(req, teeID)
		require.ErrorContains(t, err, "teeID does not match")
	})

	t.Run("no admin public keys", func(t *testing.T) {
		req := baseReq
		req.ConfigConstants.AdminsPublicKeys = []wallet.PublicKey{}
		err := CheckKeyGenerate(req, teeID)
		require.ErrorContains(t, err, "no admin public keys")
	})

	t.Run("admin threshold is zero", func(t *testing.T) {
		req := baseReq
		req.ConfigConstants.AdminsThreshold = 0
		err := CheckKeyGenerate(req, teeID)
		require.ErrorContains(t, err, "admins threshold cannot be zero")
	})

	t.Run("admins threshold > len(admins)", func(t *testing.T) {
		req := baseReq
		req.ConfigConstants.AdminsThreshold = 2
		req.ConfigConstants.AdminsPublicKeys = []wallet.PublicKey{adminPubKey}
		err := CheckKeyGenerate(req, teeID)
		require.ErrorContains(t, err, "admins threshold cannot be greater")
	})

	t.Run("cosigners threshold > len(cosigners)", func(t *testing.T) {
		req := baseReq
		req.ConfigConstants.CosignersThreshold = 2
		req.ConfigConstants.Cosigners = []common.Address{common.HexToAddress("0x1")}
		err := CheckKeyGenerate(req, teeID)
		require.ErrorContains(t, err, "cosigners threshold cannot be greater")
	})

	t.Run("signing algo is not supported", func(t *testing.T) {
		req := baseReq
		req.SigningAlgo = common.HexToHash("0xabc123")
		err := CheckKeyGenerate(req, teeID)
		require.ErrorContains(t, err, "signing algorithm not supported")
	})
}

func TestParseKeyGenerate(t *testing.T) {
	t.Run("successfully parse valid key generation data", func(t *testing.T) {
		kg := createKeyGenerateRequest(
			common.HexToAddress("0xCAFE"),
			common.HexToHash("0xADD"),
			110,
			EVMType,
			EVMAlgo,
			[]wallet.PublicKey{{X: [32]byte{1}, Y: [32]byte{2}}},
			[]common.Address{common.HexToAddress("0xF1")},
		)

		data, err := structs.Encode(wallet.MessageArguments[op.KeyGenerate], &kg)
		require.NoError(t, err)

		i := &instruction.DataFixed{
			OriginalMessage: data,
		}
		parsed, err := ParseKeyGenerate(i)
		require.NoError(t, err)
		require.Equal(t, kg.TeeId, parsed.TeeId)
		require.Equal(t, kg.KeyId, parsed.KeyId)
		require.Equal(t, kg.WalletId, parsed.WalletId)
		require.Equal(t, kg.KeyType, parsed.KeyType)
		require.Equal(t, kg.SigningAlgo, parsed.SigningAlgo)
		require.Equal(t, kg.ConfigConstants.AdminsPublicKeys, parsed.ConfigConstants.AdminsPublicKeys)
		require.Equal(t, kg.ConfigConstants.AdminsThreshold, parsed.ConfigConstants.AdminsThreshold)
		require.Equal(t, kg.ConfigConstants.Cosigners, parsed.ConfigConstants.Cosigners)
		require.Equal(t, kg.ConfigConstants.CosignersThreshold, parsed.ConfigConstants.CosignersThreshold)
	})

	t.Run("invalid parse data", func(t *testing.T) {
		badInstruction := &instruction.DataFixed{OriginalMessage: []byte{0xde, 0xad, 0xbe, 0xef}}
		_, err := ParseKeyGenerate(badInstruction)
		require.Error(t, err, "ParseKeyGenerate should fail with invalid encoded data")
	})
}

func TestExtractKeyExistence(t *testing.T) {
	teePrivKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	teeID := crypto.PubkeyToAddress(teePrivKey.PublicKey)
	_, adminsPubKeys := generateAdminKeyPair(t)

	t.Run("valid existence proof returns correct value", func(t *testing.T) {
		kg := createKeyGenerateRequest(
			teeID,
			common.HexToHash("0x42"),
			31337,
			EVMType,
			EVMAlgo,
			adminsPubKeys,
			[]common.Address{},
		)

		w := createTestWallet(t, kg)
		// Construct key existence proof
		keyExistence := w.KeyExistenceProof(teeID)
		keyExistenceBytes, err := structs.Encode(wallet.KeyExistenceStructArg, keyExistence)
		require.NoError(t, err)

		// Sign the hash
		hash := crypto.Keccak256(keyExistenceBytes)
		signature, err := utils.Sign(hash, teePrivKey)
		require.NoError(t, err)

		// Build SignedKeyExistenceProof struct and encode it
		signedProof := struct {
			KeyExistence hexutil.Bytes `json:"keyExistence"`
			Signature    hexutil.Bytes `json:"signature"`
		}{
			KeyExistence: keyExistenceBytes,
			Signature:    signature,
		}
		proofJSON, err := json.Marshal(signedProof)
		require.NoError(t, err)

		ret, err := ExtractKeyExistence(proofJSON, teeID)
		require.NoError(t, err)
		require.NotNil(t, ret)
		require.Equal(t, keyExistence.WalletId, ret.WalletId)
		require.Equal(t, keyExistence.KeyId, ret.KeyId)
		require.Equal(t, keyExistence.KeyType, ret.KeyType)
		require.Equal(t, keyExistence.SigningAlgo, ret.SigningAlgo)
		require.Equal(t, keyExistence.ConfigConstants.AdminsPublicKeys, ret.ConfigConstants.AdminsPublicKeys)
		require.Equal(t, keyExistence.ConfigConstants.AdminsThreshold, ret.ConfigConstants.AdminsThreshold)
		require.Equal(t, keyExistence.ConfigConstants.Cosigners, ret.ConfigConstants.Cosigners)
		require.Equal(t, keyExistence.ConfigConstants.CosignersThreshold, ret.ConfigConstants.CosignersThreshold)
		require.Equal(t, keyExistence.Restored, ret.Restored)
		require.Equal(t, keyExistence.SettingsVersion, ret.SettingsVersion)
		require.Equal(t, keyExistence.Settings, ret.Settings)
	})

	t.Run("fails on malformed json", func(t *testing.T) {
		_, err := ExtractKeyExistence([]byte("not a json"), teeID)
		require.Error(t, err)
	})

	t.Run("fails on missing expected fields in json", func(t *testing.T) {
		bad := []byte(`{}`)
		_, err := ExtractKeyExistence(bad, teeID)
		require.Error(t, err)
	})
}

func TestParseKeyDelete(t *testing.T) {
	nonce := big.NewInt(123)
	kgDelete := wallet.ITeeWalletKeyManagerKeyDelete{
		TeeId:    common.HexToAddress("0xdeadbeef"),
		WalletId: common.HexToHash("0x01"),
		KeyId:    1,
		Nonce:    nonce,
	}

	encBytes, err := structs.Encode(wallet.MessageArguments[op.KeyDelete], kgDelete)
	require.NoError(t, err)

	instructionData := &instruction.DataFixed{
		OriginalMessage: encBytes,
	}

	got, err := ParseKeyDelete(instructionData)
	require.NoError(t, err)
	require.Equal(t, kgDelete.TeeId, got.TeeId)
	require.Equal(t, kgDelete.WalletId, got.WalletId)
	require.Equal(t, kgDelete.KeyId, got.KeyId)
	require.Equal(t, 0, kgDelete.Nonce.Cmp(got.Nonce))

	t.Run("invalid decode returns error", func(t *testing.T) {
		badData := &instruction.DataFixed{OriginalMessage: []byte{0xde, 0xad, 0xbe, 0xef}}
		_, err := ParseKeyDelete(badData)
		require.Error(t, err)
	})
}

func TestParseKeyDataProviderRestore(t *testing.T) {
	t.Run("successfully parse valid KeyDataProviderRestore", func(t *testing.T) {
		nonce := big.NewInt(4242)
		restoreReq := wallet.ITeeWalletBackupManagerKeyDataProviderRestore{
			TeePublicKey: wallet.PublicKey{},
			BackupId: wallet.ITeeWalletBackupManagerBackupId{
				TeeId:         common.HexToAddress("0xdeadbeef"),
				WalletId:      common.HexToHash("0x01"),
				KeyId:         1,
				KeyType:       EVMType,
				SigningAlgo:   EVMAlgo,
				PublicKey:     []byte{0x12, 0x34, 0x56},
				RewardEpochId: 1,
				RandomNonce:   common.HexToHash("0xfeedfeed"),
			},
			BackupUrl: "https://example.com/backup",
			Nonce:     nonce,
		}

		enc, err := structs.Encode(wallet.MessageArguments[op.KeyDataProviderRestore], restoreReq)
		require.NoError(t, err)
		data := &instruction.DataFixed{OriginalMessage: enc}

		got, err := ParseKeyDataProviderRestore(data)
		require.NoError(t, err)
		require.Equal(t, restoreReq.TeePublicKey, got.TeePublicKey)
		require.Equal(t, restoreReq.BackupId, got.BackupId)
		require.Equal(t, restoreReq.BackupUrl, got.BackupUrl)
		require.Equal(t, 0, restoreReq.Nonce.Cmp(got.Nonce))
	})

	t.Run("bad struct returns error", func(t *testing.T) {
		bad := &instruction.DataFixed{OriginalMessage: []byte{0xfa, 0xce}}
		_, err := ParseKeyDataProviderRestore(bad)
		require.Error(t, err)
	})
}
