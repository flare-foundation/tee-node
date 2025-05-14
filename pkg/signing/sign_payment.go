package signing

import (
	"crypto/ecdsa"
	"encoding/hex"

	"github.com/pkg/errors"

	"tee-node/pkg/utils"
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
