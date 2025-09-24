package wallets

import (
	"crypto/ecdsa"
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
	PrivateKey  *ecdsa.PrivateKey
	Address     common.Address
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
	sk, err := crypto.GenerateKey()
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
		Address:            crypto.PubkeyToAddress(sk.PublicKey),
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

// CopyWallet returns a deep copy of the wallet structure.
func CopyWallet(inputWallet *Wallet) *Wallet {
	walletCopy := &Wallet{
		WalletID:    inputWallet.WalletID,
		KeyID:       inputWallet.KeyID,
		PrivateKey:  crypto.ToECDSAUnsafe(inputWallet.PrivateKey.D.Bytes()),
		Address:     inputWallet.Address,
		KeyType:     inputWallet.KeyType,
		SigningAlgo: inputWallet.SigningAlgo,

		Restored: inputWallet.Restored,

		AdminPublicKeys:    make([]*ecdsa.PublicKey, len(inputWallet.AdminPublicKeys)),
		AdminsThreshold:    inputWallet.AdminsThreshold,
		Cosigners:          make([]common.Address, len(inputWallet.Cosigners)),
		CosignersThreshold: inputWallet.CosignersThreshold,

		SettingsVersion: inputWallet.SettingsVersion,
		Settings:        make([]byte, len(inputWallet.Settings)),

		Status: &WalletStatus{
			Nonce:        inputWallet.Status.Nonce,
			StatusCode:   inputWallet.Status.StatusCode,
			PausingNonce: inputWallet.Status.PausingNonce,
		},
	}
	copy(walletCopy.AdminPublicKeys, inputWallet.AdminPublicKeys)
	copy(walletCopy.Cosigners, inputWallet.Cosigners)
	copy(walletCopy.Settings, inputWallet.Settings)

	return walletCopy
}

// WalletToKeyExistenceProof builds a key existence proof for the supplied
// wallet.
func WalletToKeyExistenceProof(inputWallet *Wallet, teeID common.Address) *wallet.ITeeWalletKeyManagerKeyExistence {
	adminPubKeys := make([]wallet.PublicKey, len(inputWallet.AdminPublicKeys))
	for i, pubKey := range inputWallet.AdminPublicKeys {
		pkt := types.PubKeyToStruct(pubKey)

		adminPubKeys[i] = wallet.PublicKey{
			X: pkt.X,
			Y: pkt.Y,
		}
	}

	return &wallet.ITeeWalletKeyManagerKeyExistence{
		TeeId:       teeID,
		WalletId:    inputWallet.WalletID,
		KeyId:       inputWallet.KeyID,
		KeyType:     inputWallet.KeyType,
		SigningAlgo: inputWallet.SigningAlgo,
		PublicKey:   types.PubKeyToBytes(&inputWallet.PrivateKey.PublicKey),
		Nonce:       new(big.Int).SetUint64(inputWallet.Status.Nonce),
		Restored:    inputWallet.Restored,
		ConfigConstants: wallet.ITeeWalletKeyManagerKeyConfigConstants{
			AdminsPublicKeys:   adminPubKeys,
			AdminsThreshold:    inputWallet.AdminsThreshold,
			Cosigners:          inputWallet.Cosigners,
			CosignersThreshold: inputWallet.CosignersThreshold,
		},
		SettingsVersion: inputWallet.SettingsVersion,
		Settings:        inputWallet.Settings,
	}
}
