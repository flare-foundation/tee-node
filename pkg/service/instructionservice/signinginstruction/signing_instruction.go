package signinginstruction

import (
	"encoding/json"
	api "tee-node/api/types"
	"tee-node/pkg/service/actionservice/walletactions"
	"tee-node/pkg/signing"
	"tee-node/pkg/utils"
	"tee-node/pkg/wallets"

	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/pkg/errors"
)

func SignPaymentTransaction(instructionData *instruction.DataFixed) ([]byte, error) {
	// TODO:  ParseSignPaymentRequest must return keyID
	originalMessage, err := api.ParseSignPaymentRequest(instructionData)
	if err != nil {
		return nil, err
	}

	var additionalFixedMessage api.SignPaymentAdditionalFixedMessage
	err = json.Unmarshal(instructionData.AdditionalFixedMessage, &additionalFixedMessage)
	if err != nil {
		return nil, err
	}

	signingWallet, err := wallets.GetWallet(wallets.WalletKeyIdPair{WalletId: originalMessage.WalletId, KeyId: additionalFixedMessage.KeyId})
	if err != nil {
		return nil, err
	}

	paused, err := walletactions.IsWalletPaused(signingWallet.WalletId, signingWallet.KeyId)
	if err != nil {
		return nil, err
	}
	if paused {
		return nil, errors.New("wallet is paused")
	}

	txnSignature, err := signing.SignXrpPayment(additionalFixedMessage.PaymentHash, signingWallet.PrivateKey)
	if err != nil {
		return nil, err
	}

	return txnSignature, nil
}

func XrpReissue(instructionData *instruction.DataFixed) ([]byte, error) {
	return nil, errors.New("XRP RESISSUE command not implemented yet")
}

func GetPaymentSignature(instructionData *instruction.DataFixed, result []byte) (*api.GetPaymentSignatureResponse, error) {
	signPaymentRequest, err := api.ParseSignPaymentRequest(instructionData)
	if err != nil {
		return nil, err
	}

	var additionalFixedMessage api.SignPaymentAdditionalFixedMessage
	err = json.Unmarshal(instructionData.AdditionalFixedMessage, &additionalFixedMessage)
	if err != nil {
		return nil, err
	}

	walletKeyIdPair := wallets.WalletKeyIdPair{WalletId: signPaymentRequest.WalletId, KeyId: additionalFixedMessage.KeyId}
	signingWallet, err := wallets.GetWallet(walletKeyIdPair)
	if err != nil {
		return nil, err
	}

	xrpAccountAddress, _ := wallets.GetXrpAddress(walletKeyIdPair)
	signingPubKey := utils.SerializeCompressed(&signingWallet.PrivateKey.PublicKey)

	return &api.GetPaymentSignatureResponse{
		Account:       xrpAccountAddress,
		TxnSignature:  result,
		PaymentHash:   additionalFixedMessage.PaymentHash,
		SigningPubKey: signingPubKey}, nil
}
