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
	State      Encoder
}

type NodeInfo struct {
	TeeId     common.Address // The ethereum address of the node, derived from the PrivateKey
	PublicKey tee.PublicKey
	State     Encoder
}

type Encoder interface {
	// Encode ABI encodes the state
	Encode() ([]byte, error)
}

func GetStateInfo() (*Encoder, error) {
	return &node.State, nil
}

func InitNode(state Encoder) error {
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

func GetTeeId() common.Address {
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
