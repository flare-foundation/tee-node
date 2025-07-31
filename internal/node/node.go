package node

import (
	"crypto/ecdsa"

	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/tee"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

var node = Node{}

type Node struct {
	TeeId      common.Address // The ethereum address of the node, derived from the PrivateKey
	PrivateKey *ecdsa.PrivateKey
	State      State
}

type NodeInfo struct {
	TeeId     common.Address // The ethereum address of the node, derived from the PrivateKey
	PublicKey tee.PublicKey
	State     State
}

type State interface {
	// Encode ABI encodes the state
	State() (tee.ITeeAvailabilityCheckTeeState, error)
}

type ZeroState struct{}

func (ZeroState) State() (tee.ITeeAvailabilityCheckTeeState, error) {
	return tee.ITeeAvailabilityCheckTeeState{
		SystemState:        []byte{},
		SystemStateVersion: [32]byte{},
		State:              []byte{},
		StateVersion:       [32]byte{},
	}, nil
}

func NodeState() (tee.ITeeAvailabilityCheckTeeState, error) {
	return node.State.State()
}

func InitNode(state State) error {
	var err error
	node.PrivateKey, err = utils.GenerateEthereumPrivateKey()
	if err != nil {
		return err
	}

	address := crypto.PubkeyToAddress(node.PrivateKey.PublicKey)
	node.TeeId = address
	node.State = state

	return nil
}

func GetNodeInfo() NodeInfo {
	return NodeInfo{
		TeeId:     node.TeeId,
		PublicKey: types.PubKeyToStruct(&node.PrivateKey.PublicKey),
		State:     node.State,
	}
}

func TeeID() common.Address {
	return node.TeeId
}

func Sign(msgHash []byte) ([]byte, error) {
	return utils.Sign(msgHash, node.PrivateKey)
}

func Decrypt(cipher []byte) ([]byte, error) {
	privKeyDecryption := ecies.ImportECDSA(node.PrivateKey)
	plaintext, err := privKeyDecryption.Decrypt(cipher, nil, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
