package policyutils

import (
	"crypto/ecdsa"
	"errors"

	"github.com/flare-foundation/tee-node/pkg/types"

	commonpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func processPolicyPublicKeys(publicKeys []types.PublicKey, sigPolicy *commonpolicy.SigningPolicy) (map[common.Address]*ecdsa.PublicKey, error) {
	if len(publicKeys) != len(sigPolicy.Voters.Voters()) {
		return nil, errors.New("the number of public keys and the number of voters do not match")
	}

	pubKeysMap := make(map[common.Address]*ecdsa.PublicKey)
	for i, pubKey := range publicKeys {
		pubKeyECDSA, err := types.ParsePubKey(pubKey)
		if err != nil {
			return nil, err
		}
		address := crypto.PubkeyToAddress(*pubKeyECDSA)
		if address != sigPolicy.Voters.Voters()[i] {
			return nil, errors.New("public key and address do not match")
		}

		pubKeysMap[address] = pubKeyECDSA
	}

	return pubKeysMap, nil
}
