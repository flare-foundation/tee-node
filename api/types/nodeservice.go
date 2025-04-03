package types

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
)

type GetNodeInfoRequest struct {
	Nonce string
}

type GetNodeInfoData struct {
	Id     common.Address
	Status string

	EncryptionPublicKey string
	SigningPublicKey    ECDSAPublicKey

	SigningPolicyHash string
}

type GetNodeInfoResponse struct {
	Data  GetNodeInfoData
	Token string
}

func (d *GetNodeInfoData) Hash() (string, error) {
	hashFunc := sha256.New()
	dBytes, err := json.Marshal(d)
	if err != nil {
		return "", err
	}

	_, err = hashFunc.Write(dBytes)
	if err != nil {
		return "", err
	}

	hashBytes := hashFunc.Sum(nil)

	return hex.EncodeToString(hashBytes), nil
}
