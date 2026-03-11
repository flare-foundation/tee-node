package wallets

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
	"github.com/flare-foundation/go-flare-common/pkg/tee/xrpl"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/encoding"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/hash"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing/secp256k1"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing/utils"
	"github.com/stretchr/testify/require"
)

func TestSignSHA512HalfSecp256k1ECDSABasic(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	message := []byte("test message for signing")

	signature, err := signSHA512HalfSecp256k1ECDSA(privateKey, message)
	require.NoError(t, err)

	require.Equal(t, 65, len(signature))

	messageHash := hash.Sha512Half(message)
	recoveredPubKey, err := crypto.SigToPub(messageHash, signature)
	require.NoError(t, err)

	require.Equal(t, privateKey.PublicKey, *recoveredPubKey)
}

func TestSignKeccak256Secp256k1ECDSABasic(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	message := []byte("test message for signing")

	signature, err := signKeccak256Secp256k1ECDSA(privateKey, message)
	require.NoError(t, err)

	require.Equal(t, 65, len(signature))

	messageHash := crypto.Keccak256(message)
	recoveredPubKey, err := crypto.SigToPub(messageHash, signature)
	require.NoError(t, err)

	require.Equal(t, privateKey.PublicKey, *recoveredPubKey)
}

func TestSignEthTransaction(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	// Create a simple Ethereum transaction
	to := common.HexToAddress("0x742d35Cc6634C0532925a3b8D0C9e0e7C0C0C0C0")
	chainID := big.NewInt(1)
	value := big.NewInt(1000000000000000000) // 1 ETH in wei
	gasLimit := uint64(22000)
	nonce := uint64(0)
	data := []byte{}
	tipCap := big.NewInt(1000000000)
	gasFeeCap := big.NewInt(2000000000)

	txData := types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: tipCap,
		GasFeeCap: gasFeeCap,
		Gas:       gasLimit,
		To:        &to,
		Value:     value,
		Data:      data,
	}

	encodedTx, err := encodeToSign(&txData, chainID)
	require.NoError(t, err)

	signature, err := signKeccak256Secp256k1ECDSA(privateKey, encodedTx)
	require.NoError(t, err)

	v := big.NewInt(int64(signature[64]))
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])

	tx := types.NewTx(&txData)

	signedTx, err := types.SignTx(tx, types.NewCancunSigner(chainID), privateKey)
	require.NoError(t, err)

	ve, re, se := signedTx.RawSignatureValues()

	require.Equal(t, ve, v)
	require.Equal(t, re, r)
	require.Equal(t, se, s)
}

func encodeToSign(tx *types.DynamicFeeTx, chainID *big.Int) ([]byte, error) {
	buf := bytes.Buffer{}
	buf.WriteByte(0x02)
	err := rlp.Encode(&buf, []any{
		chainID,
		tx.Nonce,
		tx.GasTipCap,
		tx.GasFeeCap,
		tx.Gas,
		tx.To,
		tx.Value,
		tx.Data,
		tx.AccessList,
	})

	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func TestXRPLSigning(t *testing.T) {
	wal := setupTestWallet(t, XRPAlgo)

	originalMessage := payment.ITeePaymentsPaymentInstructionMessage{
		WalletId: wal.WalletID,
		TeeIdKeyIdPairs: []payment.TeeIdKeyIdPair{{
			TeeId: common.BytesToAddress([]byte("random")),
			KeyId: wal.KeyID,
		}},
		SenderAddress:    "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
		RecipientAddress: "rrrrrrrrrrrrrrrrrrrrrhoLvTp",
		Amount:           big.NewInt(1000000000),
		MaxFee:           big.NewInt(1000),
		FeeSchedule:      []byte{0x27, 0x10, 0x00, 0x00}, // 100% of MaxFee, 0s delay
		PaymentReference: [32]byte{},
		Nonce:            uint64(0),
		SubNonce:         uint64(0),
		BatchEndTs:       uint64(0),
	}

	tx, err := xrpl.PaymentTxFromInstruction(originalMessage, 0)
	require.NoError(t, err)

	pk := ToECDSAUnsafe(wal.PrivateKey)

	sigItem, err := secp256k1.SignTxMultisig(tx, pk)
	require.NoError(t, err)

	encoded, err := encoding.Encode(tx, true)
	require.NoError(t, err)

	accID := secp256k1.PrvToID(pk)

	msg, err := utils.Prepare(encoded, true, accID)
	require.NoError(t, err)

	sig, err := wal.Sign(msg)
	require.NoError(t, err)

	sigM, err := secp256k1.MarshalRecID(sig)
	require.NoError(t, err)

	sigDER := sigM.DER()

	require.Equal(t, sigItem.TxnSignature, hex.EncodeToString(sigDER))
}

func setupTestWallet(t *testing.T, signingAlgo common.Hash) *Wallet {
	t.Helper()

	// Generate a test private key
	privateKey, err := GenerateKey(signingAlgo)
	require.NoError(t, err)

	seed := crypto.Keccak256(privateKey)

	// Create test wallet
	walletID := crypto.Keccak256Hash(seed)
	keyID := uint64(0)

	wallet := &Wallet{
		WalletID:    walletID,
		KeyID:       keyID,
		PrivateKey:  privateKey,
		SigningAlgo: signingAlgo,
		Status: &WalletStatus{
			Nonce:      0,
			StatusCode: 0,
		},
	}

	return wallet
}

func TestToECDSAUnsafe(t *testing.T) {
	// Test the ToECDSAUnsafe function with various inputs
	t.Run("valid private key", func(t *testing.T) {
		// Generate a valid private key
		originalKey, err := crypto.GenerateKey()
		require.NoError(t, err)

		// Convert to bytes
		keyBytes := crypto.FromECDSA(originalKey)

		// Convert back using ToECDSAUnsafe
		recoveredKey := ToECDSAUnsafe(keyBytes)

		// Verify the keys match
		require.Equal(t, originalKey.D, recoveredKey.D)
		require.Equal(t, originalKey.X, recoveredKey.X)
		require.Equal(t, originalKey.Y, recoveredKey.Y)
	})

	t.Run("invalid private key", func(t *testing.T) {
		// Use an invalid private key (short private key)
		invalidKeyBytes := common.MaxHash

		_, err := crypto.ToECDSA(invalidKeyBytes[:])
		require.Error(t, err)
		recoveredKey := ToECDSAUnsafe(invalidKeyBytes[:])

		require.Nil(t, recoveredKey.X)
		require.Nil(t, recoveredKey.Y)
	})
}
