package signing

import (
	"crypto/ecdsa"
	"encoding/hex"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"

	"tee-node/pkg/tee/utils"
)

func SignXrpPayment(paymentHash string, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	paymentHashBytes, err := hex.DecodeString(paymentHash)
	if err != nil {
		return nil, err
	}

	if len(paymentHashBytes) > 32 {
		return nil, errors.New("payment hash is too long")
	}

	txnSignature := utils.XrpSign(paymentHashBytes, privateKey)

	return txnSignature, nil
}

func CheckCosigners(cosignersSignatures map[common.Address][]byte, walletCosigners []common.Address, threshold uint64) (bool, error) {
	for cosigner := range cosignersSignatures {
		if ok := slices.Contains(walletCosigners, cosigner); !ok {
			return false, errors.New("signed by a non-cosigner")
		}
	}

	return uint64(len(cosignersSignatures)) >= threshold, nil
}
