package wallets

import (
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
)

// Wallet is a struct carrying the private key of particular wallet. It
// should never be modified (apart from WalletStatus), after being created.
type Wallet struct {
	WalletID    common.Hash
	KeyID       uint64
	PrivateKey  []byte
	KeyType     common.Hash
	SigningAlgo common.Hash

	Restored bool

	AdminPublicKeys    []*ecdsa.PublicKey
	AdminsThreshold    uint64
	Cosigners          []common.Address
	CosignersThreshold uint64

	SettingsVersion common.Hash
	Settings        hexutil.Bytes

	Status *WalletStatus
}

type WalletStatus struct {
	Nonce        uint64
	PausingNonce common.Hash
	StatusCode   uint8
}

// GenerateNewKey creates a wallet from the key generate instruction payload.
func GenerateNewKey(kg wallet.ITeeWalletKeyManagerKeyGenerate) (*Wallet, error) {
	sk, err := GenerateKey(kg.SigningAlgo)
	if err != nil {
		return nil, err
	}
	adminsPubKeys, err := utils.ParsePubKeys(kg.ConfigConstants.AdminsPublicKeys)
	if err != nil {
		return nil, err
	}

	newWallet := &Wallet{
		WalletID:           kg.WalletId,
		KeyID:              kg.KeyId,
		PrivateKey:         sk,
		KeyType:            kg.KeyType,
		SigningAlgo:        kg.SigningAlgo,
		Restored:           false,
		AdminPublicKeys:    adminsPubKeys,
		AdminsThreshold:    kg.ConfigConstants.AdminsThreshold,
		Cosigners:          kg.ConfigConstants.Cosigners,
		CosignersThreshold: kg.ConfigConstants.CosignersThreshold,
		SettingsVersion:    common.Hash{},
		Settings:           make(hexutil.Bytes, 0),

		Status: &WalletStatus{Nonce: 0, StatusCode: 0},
	}

	return newWallet, nil
}

// Copy returns a deep copy of the wallet.
func (w *Wallet) Copy() *Wallet {
	walletCopy := &Wallet{
		WalletID:    w.WalletID,
		KeyID:       w.KeyID,
		PrivateKey:  append(make([]byte, 0, len(w.PrivateKey)), w.PrivateKey...),
		KeyType:     w.KeyType,
		SigningAlgo: w.SigningAlgo,

		Restored: w.Restored,

		AdminPublicKeys:    make([]*ecdsa.PublicKey, len(w.AdminPublicKeys)),
		AdminsThreshold:    w.AdminsThreshold,
		Cosigners:          make([]common.Address, len(w.Cosigners)),
		CosignersThreshold: w.CosignersThreshold,

		SettingsVersion: w.SettingsVersion,
		Settings:        make([]byte, len(w.Settings)),

		Status: &WalletStatus{
			Nonce:        w.Status.Nonce,
			StatusCode:   w.Status.StatusCode,
			PausingNonce: w.Status.PausingNonce,
		},
	}
	copy(walletCopy.AdminPublicKeys, w.AdminPublicKeys)
	copy(walletCopy.Cosigners, w.Cosigners)
	copy(walletCopy.Settings, w.Settings)

	return walletCopy
}

// KeyExistenceProof builds a key existence proof for the wallet.
func (w *Wallet) KeyExistenceProof(teeID common.Address) *wallet.ITeeWalletKeyManagerKeyExistence {
	adminPubKeys := make([]wallet.PublicKey, len(w.AdminPublicKeys))
	for i, pubKey := range w.AdminPublicKeys {
		pkt := types.PubKeyToStruct(pubKey)

		adminPubKeys[i] = wallet.PublicKey{
			X: pkt.X,
			Y: pkt.Y,
		}
	}

	return &wallet.ITeeWalletKeyManagerKeyExistence{
		TeeId:       teeID,
		WalletId:    w.WalletID,
		KeyId:       w.KeyID,
		KeyType:     w.KeyType,
		SigningAlgo: w.SigningAlgo,
		PublicKey:   w.pubKey(),
		Nonce:       new(big.Int).SetUint64(w.Status.Nonce),
		Restored:    w.Restored,
		ConfigConstants: wallet.ITeeWalletKeyManagerKeyConfigConstants{
			AdminsPublicKeys:   adminPubKeys,
			AdminsThreshold:    w.AdminsThreshold,
			Cosigners:          w.Cosigners,
			CosignersThreshold: w.CosignersThreshold,
		},
		SettingsVersion: w.SettingsVersion,
		Settings:        w.Settings,
	}
}

// Sign returns a cryptographic signature of the message using the wallet's signing algorithm.
func (w *Wallet) Sign(msg []byte) ([]byte, error) {
	switch w.SigningAlgo {
	case XRPAlgo:
		prv := ToECDSAUnsafe(w.PrivateKey)
		return signSHA512HalfSecp256k1ECDSA(prv, msg)
	case EVMAlgo:
		prv := ToECDSAUnsafe(w.PrivateKey)
		return signKeccak256Secp256k1ECDSA(prv, msg)
	default:
		return nil, errors.New("unsupported signing algorithm")
	}
}

// Decrypt decrypts an encrypted message using the supplied private key based on type of key.
func (w *Wallet) Decrypt(cipher []byte) ([]byte, error) {
	switch w.SigningAlgo {
	case XRPAlgo, EVMAlgo:
		prv := ToECDSAUnsafe(w.PrivateKey)
		prvDecryption, err := utils.ECDSAPrivKeyToECIES(prv)
		if err != nil {
			return nil, err
		}
		plaintext, err := prvDecryption.Decrypt(cipher, nil, nil)
		if err != nil {
			return nil, err
		}

		return plaintext, nil

	default:
		return nil, errors.New("wallet does not support decryption")
	}
}

func (w *Wallet) pubKey() []byte {
	switch w.SigningAlgo {
	case XRPAlgo, EVMAlgo:
		prv := ToECDSAUnsafe(w.PrivateKey)
		return types.PubKeyToBytes(&prv.PublicKey)
	default:
		return []byte{}
	}
}

// GenerateKey creates a new private key for the signing algorithm.
func GenerateKey(signingAlgo common.Hash) ([]byte, error) {
	switch signingAlgo {
	case XRPAlgo, EVMAlgo:
		sk, err := crypto.GenerateKey()
		if err != nil {
			return nil, err
		}
		return common.BigToHash(sk.D).Bytes(), nil
	default:
		return nil, errors.New("unsupported signing algorithm")
	}
}

// ToECDSAUnsafe converts a private key from byte slice to *ecdsa.PrivateKey.
// Use only if you are sure that bytes represent a valid private key.
//
// Based on go-ethereum's crypto.ToECDSAUnsafe.
func ToECDSAUnsafe(sk []byte) *ecdsa.PrivateKey {
	priv := new(ecdsa.PrivateKey)
	priv.Curve = crypto.S256()
	priv.D = new(big.Int).SetBytes(sk)
	priv.PublicKey.X, priv.PublicKey.Y = priv.Curve.ScalarBaseMult(sk) //nolint:staticcheck // we keep PublicKey for clarity

	return priv
}
