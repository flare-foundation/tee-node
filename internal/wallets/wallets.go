package wallets

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing/secp256k1"
)

// Wallet is a struct carrying the private key of particular wallet. It
// should never be modified, after being created.
type Wallet struct {
	WalletId   common.Hash
	KeyId      uint64
	PrivateKey *ecdsa.PrivateKey
	Address    common.Address
	XrpAddress string
	Restored   bool

	AdminPublicKeys    []*ecdsa.PublicKey
	AdminsThreshold    uint64
	Cosigners          []common.Address
	CosignersThreshold uint64
	OpType             [32]byte
	OpTypeConstants    []byte

	Status *WalletStatus
}

type WalletStatus struct {
	Nonce        uint64
	PausingNonce common.Hash
	StatusCode   uint8
}

func CreateNewWallet(walletInfo wallet.ITeeWalletKeyManagerKeyGenerate) (*Wallet, error) {
	sk, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	xrpAddress := secp256k1.PrvToAddress(sk)

	adminsPubKeys, err := utils.ParsePubKeys(walletInfo.ConfigConstants.AdminsPublicKeys)
	if err != nil {
		return nil, err
	}

	newWallet := &Wallet{
		WalletId:           walletInfo.WalletId,
		KeyId:              walletInfo.KeyId,
		PrivateKey:         sk,
		Address:            crypto.PubkeyToAddress(sk.PublicKey),
		XrpAddress:         xrpAddress,
		AdminPublicKeys:    adminsPubKeys,
		AdminsThreshold:    walletInfo.ConfigConstants.AdminsThreshold,
		Cosigners:          walletInfo.ConfigConstants.Cosigners,
		CosignersThreshold: walletInfo.ConfigConstants.CosignersThreshold,
		OpType:             walletInfo.OpType,
		OpTypeConstants:    walletInfo.ConfigConstants.OpTypeConstants,
		Status:             &WalletStatus{Nonce: 0, StatusCode: 0},
	}

	return newWallet, nil
}

func CopyWallet(inputWallet *Wallet) *Wallet {
	walletCopy := &Wallet{
		WalletId:   inputWallet.WalletId,
		KeyId:      inputWallet.KeyId,
		PrivateKey: crypto.ToECDSAUnsafe(inputWallet.PrivateKey.D.Bytes()),
		Address:    inputWallet.Address,
		XrpAddress: inputWallet.XrpAddress,
		Restored:   inputWallet.Restored,

		AdminPublicKeys:    make([]*ecdsa.PublicKey, len(inputWallet.AdminPublicKeys)),
		AdminsThreshold:    inputWallet.AdminsThreshold,
		Cosigners:          make([]common.Address, len(inputWallet.Cosigners)),
		CosignersThreshold: inputWallet.CosignersThreshold,
		OpType:             inputWallet.OpType,
		OpTypeConstants:    make([]byte, len(inputWallet.OpTypeConstants)),

		Status: &WalletStatus{
			Nonce:        inputWallet.Status.Nonce,
			StatusCode:   inputWallet.Status.StatusCode,
			PausingNonce: inputWallet.Status.PausingNonce,
		},
	}
	copy(walletCopy.AdminPublicKeys, inputWallet.AdminPublicKeys)
	copy(walletCopy.Cosigners, inputWallet.Cosigners)
	copy(walletCopy.OpTypeConstants, inputWallet.OpTypeConstants)

	return walletCopy
}

func WalletToKeyExistenceProof(inputWallet *Wallet, teeId common.Address) *wallet.ITeeWalletKeyManagerKeyExistence {
	adminPubKeys := make([]wallet.PublicKey, len(inputWallet.AdminPublicKeys))
	for i, pubKey := range inputWallet.AdminPublicKeys {
		pkt := types.PubKeyToStruct(pubKey)

		adminPubKeys[i] = wallet.PublicKey{
			X: pkt.X,
			Y: pkt.Y,
		}
	}

	return &wallet.ITeeWalletKeyManagerKeyExistence{
		TeeId:      teeId,
		WalletId:   inputWallet.WalletId,
		KeyId:      inputWallet.KeyId,
		OpType:     inputWallet.OpType,
		PublicKey:  types.PubKeyToBytes(&inputWallet.PrivateKey.PublicKey),
		Nonce:      new(big.Int).SetUint64(inputWallet.Status.Nonce),
		PauseNonce: new(big.Int).SetBytes(inputWallet.Status.PausingNonce[:]),
		Status:     inputWallet.Status.StatusCode,
		Restored:   inputWallet.Restored,
		AddressStr: inputWallet.XrpAddress,
		ConfigConstants: wallet.ITeeWalletKeyManagerKeyConfigConstants{
			AdminsPublicKeys:   adminPubKeys,
			AdminsThreshold:    inputWallet.AdminsThreshold,
			Cosigners:          inputWallet.Cosigners,
			CosignersThreshold: inputWallet.CosignersThreshold,
			OpTypeConstants:    inputWallet.OpTypeConstants,
		},
		ConfigSettings: wallet.ITeeWalletKeyManagerKeyConfigSettings{}, // V2
	}
}
