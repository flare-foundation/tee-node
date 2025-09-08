package wallets

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/signing/secp256k1"
)

// Wallet is a struct carrying the private key of particular wallet. It
// should never be modified (apart from WalletStatus), after being created.
type Wallet struct {
	WalletID        common.Hash
	KeyID           uint64
	PrivateKey      *ecdsa.PrivateKey
	Address         common.Address
	ExternalAddress string
	Restored        bool

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

func GenerateNewKey(kg wallet.ITeeWalletKeyManagerKeyGenerate) (*Wallet, error) {
	sk, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	externalAddress := ExternalAddress(kg.OpType, sk)

	adminsPubKeys, err := utils.ParsePubKeys(kg.ConfigConstants.AdminsPublicKeys)
	if err != nil {
		return nil, err
	}

	newWallet := &Wallet{
		WalletID:           kg.WalletId,
		KeyID:              kg.KeyId,
		PrivateKey:         sk,
		Address:            crypto.PubkeyToAddress(sk.PublicKey),
		ExternalAddress:    externalAddress,
		AdminPublicKeys:    adminsPubKeys,
		AdminsThreshold:    kg.ConfigConstants.AdminsThreshold,
		Cosigners:          kg.ConfigConstants.Cosigners,
		CosignersThreshold: kg.ConfigConstants.CosignersThreshold,
		OpType:             kg.OpType,
		OpTypeConstants:    kg.ConfigConstants.OpTypeConstants,
		Status:             &WalletStatus{Nonce: 0, StatusCode: 0},
	}

	return newWallet, nil
}

func CopyWallet(inputWallet *Wallet) *Wallet {
	walletCopy := &Wallet{
		WalletID:        inputWallet.WalletID,
		KeyID:           inputWallet.KeyID,
		PrivateKey:      crypto.ToECDSAUnsafe(inputWallet.PrivateKey.D.Bytes()),
		Address:         inputWallet.Address,
		ExternalAddress: inputWallet.ExternalAddress,
		Restored:        inputWallet.Restored,

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
		TeeId:      teeID,
		WalletId:   inputWallet.WalletID,
		KeyId:      inputWallet.KeyID,
		OpType:     inputWallet.OpType,
		PublicKey:  types.PubKeyToBytes(&inputWallet.PrivateKey.PublicKey),
		Nonce:      new(big.Int).SetUint64(inputWallet.Status.Nonce),
		PauseNonce: new(big.Int).SetBytes(inputWallet.Status.PausingNonce[:]),
		Status:     inputWallet.Status.StatusCode,
		Restored:   inputWallet.Restored,
		AddressStr: inputWallet.ExternalAddress,
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

func ExternalAddress(opType common.Hash, pk *ecdsa.PrivateKey) string {
	t := op.HashToOPType(opType)
	if t == op.XRP {
		return secp256k1.PrvToAddress(pk)
	}

	return crypto.PubkeyToAddress(pk.PublicKey).String()
}
