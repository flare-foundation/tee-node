package wallets

import (
	"crypto/ecdsa"
	"tee-node/api/types"
	"tee-node/pkg/tee/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/pkg/errors"
)

// Wallet is a struct carrying the private key of particular wallet. It
// should never be modified, after being created. Todo: check this
type Wallet struct {
	WalletId   common.Hash
	KeyId      uint64
	PrivateKey *ecdsa.PrivateKey
	Address    common.Address
	XrpAddress string
	Restored   bool

	AdminsPublicKeys   []*ecdsa.PublicKey
	AdminsThreshold    uint64
	Cosigners          []common.Address
	CosignersThreshold uint64
	OpType             [32]byte
	OpTypeConstants    []byte

	// WalletPauserAddresses         []common.Address
	// WalletPauserAddressSetupNonce big.Int
	// WalletPausingNonce            common.Hash
	// IsWalletPaused                bool
}

type WalletKeyIdPair struct {
	WalletId common.Hash
	KeyId    uint64
}

func CreateNewWallet(walletInfo wallet.ITeeWalletKeyManagerKeyGenerate) (*Wallet, error) {
	sk, err := utils.GenerateEthereumPrivateKey()
	if err != nil {
		return nil, err
	}

	sec1PubKey := utils.SerializeCompressed(&sk.PublicKey)
	xrpAddress, err := utils.GetXrpAddressFromPubkey(sec1PubKey)
	if err != nil {
		return nil, err
	}

	adminsPubKeys := make([]*ecdsa.PublicKey, len(walletInfo.ConfigConstants.AdminsPublicKeys))
	for i, key := range walletInfo.ConfigConstants.AdminsPublicKeys {
		adminsPubKeys[i], err = types.ParsePubKey(types.ECDSAPublicKey(key))
		if err != nil {
			return nil, err
		}
	}

	newWallet := &Wallet{
		WalletId:           walletInfo.WalletId,
		KeyId:              walletInfo.KeyId,
		PrivateKey:         sk,
		Address:            crypto.PubkeyToAddress(sk.PublicKey),
		XrpAddress:         xrpAddress,
		AdminsPublicKeys:   adminsPubKeys,
		AdminsThreshold:    walletInfo.ConfigConstants.AdminsThreshold,
		Cosigners:          walletInfo.ConfigConstants.Cosigners,
		CosignersThreshold: walletInfo.ConfigConstants.CosignersThreshold,
		OpType:             walletInfo.OpType,
		OpTypeConstants:    walletInfo.ConfigConstants.OpTypeConstants,
	}

	return newWallet, nil
}

func GetXrpAddress(idPair WalletKeyIdPair) (string, error) {
	walletsStorage.Lock()
	defer walletsStorage.Unlock()

	wallet, ok := walletsStorage.Storage[idPair]

	if !ok {
		return "", errors.New("wallet non-existent")
	}

	return wallet.XrpAddress, nil
}

func GetEthAddress(idPair WalletKeyIdPair) (string, error) {
	walletsStorage.Lock()
	defer walletsStorage.Unlock()

	wallet, ok := walletsStorage.Storage[idPair]
	if !ok {
		return "", errors.New("wallet non-existent")
	}

	return wallet.Address.Hex(), nil
}

func GetPublicKey(idPair WalletKeyIdPair) (*ecdsa.PublicKey, error) {
	walletsStorage.Lock()
	defer walletsStorage.Unlock()

	wallet, ok := walletsStorage.Storage[idPair]
	if !ok {
		return nil, errors.New("wallet non-existent")
	}

	return &wallet.PrivateKey.PublicKey, nil
}

func WalletToKeyExistenceProof(inputWallet *Wallet, teeId common.Address) *wallet.ITeeWalletKeyManagerKeyExistence {
	return &wallet.ITeeWalletKeyManagerKeyExistence{
		TeeId:           teeId,
		WalletId:        inputWallet.WalletId,
		KeyId:           inputWallet.KeyId,
		OpType:          inputWallet.OpType,
		PublicKey:       types.PubKeyToBytes(&inputWallet.PrivateKey.PublicKey),
		Nonce:           nil, // todo
		PauseNonce:      nil, // todo
		Status:          0,   // todo
		Restored:        inputWallet.Restored,
		AddressStr:      inputWallet.XrpAddress,
		ConfigConstants: wallet.ITeeWalletKeyManagerKeyConfigConstants{}, // todo
		ConfigSettings:  wallet.ITeeWalletKeyManagerKeyConfigSettings{},  // todo
	}
}
