package governanceactions

// import (
// 	"math/big"
// 	"tee-node/pkg/tee/node"

// 	"github.com/ethereum/go-ethereum/common"
// )

// func GetTeePausingAddresses() []common.Address {
// 	node.PausingAddressesStorage.Lock()
// 	defer node.PausingAddressesStorage.Unlock()

// 	return node.PausingAddressesStorage.TeePauserAddresses
// }

// func GetTeePausingAddressSetupNonce() big.Int {
// 	node.PausingAddressesStorage.Lock()
// 	defer node.PausingAddressesStorage.Unlock()

// 	return node.PausingAddressesStorage.TeePauserAddressSetupNonce
// }

// func IsTeePaused() bool {
// 	node.PausingNoncesStorage.Lock()
// 	defer node.PausingNoncesStorage.Unlock()

// 	return node.PausingNoncesStorage.IsTeePaused
// }

// func GetTeePausingNonce() common.Hash {
// 	node.PausingNoncesStorage.Lock()
// 	defer node.PausingNoncesStorage.Unlock()

// 	return node.PausingNoncesStorage.TeePausingNonce
// }

// func PauseTeeInternal() {
// 	node.PausingNoncesStorage.Lock()
// 	defer node.PausingNoncesStorage.Unlock()

// 	node.PausingNoncesStorage.IsTeePaused = true
// }

// func UnpauseTeeInternal() {
// 	node.PausingNoncesStorage.Lock()
// 	defer node.PausingNoncesStorage.Unlock()

// 	// regenerate the pausing nonce to prevent replay attacks
// 	node.PausingNoncesStorage.TeePausingNonce = node.GeneratePausingNonce()
// 	node.PausingNoncesStorage.IsTeePaused = false
// }

// func UpdatePausingAddressesTeeInternal(pausingAddresses []common.Address, pauserAddressSetupNonce big.Int) {
// 	node.PausingAddressesStorage.Lock()
// 	defer node.PausingAddressesStorage.Unlock()

// 	node.PausingAddressesStorage.TeePauserAddresses = pausingAddresses
// 	node.PausingAddressesStorage.TeePauserAddressSetupNonce = pauserAddressSetupNonce
// }
