package node

import (
	"crypto/ecdsa"
	"encoding/hex"
	"tee-node/internal/utils"
)

var nodeId = NodeId{}

const (
	operationalStatus     = "operational"
	pausedForUpdateStatus = "paused_for_update"
)

type NodeId struct {
	Uuid          string
	Status        string
	EncryptionKey utils.EncryptionKey
	SignatureKey  *ecdsa.PrivateKey
}

func InitNode() error {
	idBytes, err := utils.GenerateRandomBytes(32)
	if err != nil {
		return err
	}
	nodeId.Uuid = hex.EncodeToString(idBytes)

	nodeId.EncryptionKey, err = utils.GenerateEncryptionKeyPair()
	if err != nil {
		return err
	}

	nodeId.SignatureKey, err = utils.GenerateEthereumPrivateKey()
	if err != nil {
		return err
	}

	nodeId.Status = operationalStatus

	return nil
}

func GetNodeId() NodeId {
	return nodeId
}
