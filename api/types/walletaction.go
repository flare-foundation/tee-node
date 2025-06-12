package types

// import (
// 	"encoding/json"
// 	"math/big"

// 	"github.com/ethereum/go-ethereum/common"
// 	"github.com/ethereum/go-ethereum/crypto"
// )

// // ---------------------------
// type PauseWalletMessage struct {
// 	WalletId     common.Hash
// 	KeyId        uint64
// 	PausingNonce common.Hash
// }

// func (message PauseWalletMessage) Hash() (common.Hash, error) {
// 	messageBytes, err := json.Marshal(message)
// 	if err != nil {
// 		return common.Hash{}, err
// 	}
// 	return crypto.Keccak256Hash(messageBytes), nil
// }

// // ---------------------------
// type ResumeWalletMessage struct {
// 	WalletId     common.Hash
// 	KeyId        uint64
// 	PausingNonce common.Hash
// }

// func (message ResumeWalletMessage) Hash() (common.Hash, error) {
// 	messageBytes, err := json.Marshal(message)
// 	if err != nil {
// 		return common.Hash{}, err
// 	}
// 	return crypto.Keccak256Hash(messageBytes), nil
// }

// // ---------------------------
// type PausingAddressSetWalletMessage struct {
// 	PauserAddressSetupNonce big.Int
// 	WalletId                common.Hash
// 	KeyId                   uint64
// 	PausingAddresses        []common.Address
// }

// func (message PausingAddressSetWalletMessage) Hash() (common.Hash, error) {
// 	messageBytes, err := json.Marshal(message)
// 	if err != nil {
// 		return common.Hash{}, err
// 	}
// 	return crypto.Keccak256Hash(messageBytes), nil
// }
