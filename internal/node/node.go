package node

import (
	"crypto/ecdsa"
	"encoding/hex"
	"tee-node/internal/utils"
)

type NodeId struct {
	Uuid   string
	SecKey *ecdsa.PrivateKey
	PubKey *ecdsa.PublicKey
}

var nodeId = NodeId{}

func InitNode() error {
	idBytes, err := utils.GenerateRandomBytes(32)
	if err != nil {
		return err
	}
	nodeId.Uuid = hex.EncodeToString(idBytes)

	nodeId.SecKey, err = utils.GenerateEthereumPrivateKey()
	if err != nil {
		return err
	}
	nodeId.PubKey = &nodeId.SecKey.PublicKey

	return nil
}

func GetNodeId() NodeId {
	return nodeId
}
