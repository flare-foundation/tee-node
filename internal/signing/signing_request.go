package signing

import (
	"encoding/hex"
	"errors"
	"fmt"
)

type SignPaymentRequest struct {
	WalletName  string
	PaymentHash []byte
}

func NewSignPaymentRequest(walletName string, paymentHashHex string) (SignPaymentRequest, error) {
	if len(walletName) == 0 {
		return SignPaymentRequest{}, errors.New("wallet name is empty")
	}
	if paymentHashHex == "" {
		return SignPaymentRequest{}, errors.New("payment bytes are empty")
	}

	paymentHash, err := hex.DecodeString(paymentHashHex)
	if err != nil {
		return SignPaymentRequest{}, errors.New("payment bytes are empty")
	}

	return SignPaymentRequest{
		PaymentHash: paymentHash,
		WalletName:  walletName,
	}, nil
}

func (sp SignPaymentRequest) Message() string {
	paymentString := hex.EncodeToString(sp.PaymentHash)

	return fmt.Sprintf("SignPaymentRequest(%s-%s)", sp.WalletName, paymentString)
}
