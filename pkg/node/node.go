package node

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
)

type Node struct {
	teeID      common.Address // The ethereum address of the node, derived from the PrivateKey
	privateKey *ecdsa.PrivateKey
	state      State
}

type Info struct {
	TeeID     common.Address // The ethereum address of the node, derived from the PrivateKey
	PublicKey types.PublicKey
	State     State
}

type State interface {
	// Encode ABI encodes the state
	State() (types.TeeState, error)
}

type ZeroState struct{}

func (ZeroState) State() (types.TeeState, error) {
	return types.TeeState{
		SystemState:        hexutil.Bytes{},
		SystemStateVersion: common.Hash{},
		State:              hexutil.Bytes{},
		StateVersion:       common.Hash{},
	}, nil
}

// Initialize generates node's private key and sets the teeID.
func Initialize(state State) (*Node, error) {
	var privKey, err = crypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	id := crypto.PubkeyToAddress(privKey.PublicKey)

	return &Node{
		teeID:      id,
		privateKey: privKey,
		state:      state,
	}, nil
}

func (n *Node) State() (types.TeeState, error) {
	return n.state.State()
}

// Info return node's info.
func (n *Node) Info() Info {
	return Info{
		TeeID:     n.teeID,
		PublicKey: types.PubKeyToStruct(&n.privateKey.PublicKey),
		State:     n.state,
	}
}

// TeeID is the ethereum address corresponding to the node's private key.
func (n *Node) TeeID() common.Address {
	return n.teeID
}

func (n *Node) Sign(msgHash []byte) ([]byte, error) {
	return utils.Sign(msgHash, n.privateKey)
}

func (n *Node) Decrypt(cipher []byte) ([]byte, error) {
	privKeyDecryption := ecies.ImportECDSA(n.privateKey)
	plaintext, err := privKeyDecryption.Decrypt(cipher, nil, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
