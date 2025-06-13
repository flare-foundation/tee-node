package signinginstruction

import (
	"encoding/json"
	"tee-node/api/types"
	"tee-node/pkg/tee/signing"
	"tee-node/pkg/tee/utils"
	"tee-node/pkg/tee/wallets"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/pkg/errors"
)

func SignPaymentTransaction(instructionData *instruction.DataFixed, cosigners map[common.Address][]byte) ([]byte, error) {
	// TODO:  ParseSignPaymentRequest must return keyID
	originalMessage, err := types.ParseSignPaymentRequest(instructionData)
	if err != nil {
		return nil, err
	}

	var additionalFixedMessage types.SignPaymentAdditionalFixedMessage
	err = json.Unmarshal(instructionData.AdditionalFixedMessage, &additionalFixedMessage)
	if err != nil {
		return nil, err
	}

	walletKeyIdPair := wallets.WalletKeyIdPair{WalletId: originalMessage.WalletId, KeyId: additionalFixedMessage.KeyId}
	wallets.Storage.RLock()
	signingWallet, err := wallets.Storage.GetWallet(walletKeyIdPair)
	wallets.Storage.RUnlock()
	if err != nil {
		return nil, err
	}

	check, err := signing.CheckCosigners(cosigners, signingWallet.Cosigners, signingWallet.CosignersThreshold)
	if err != nil {
		return nil, err
	}
	if !check {
		return nil, errors.New("cosigners threshold not reached")
	}

	// if signingWallet.IsWalletPaused {
	// 	return nil, errors.New("wallet is paused")
	// }

	txnSignature, err := signing.SignXrpPayment(additionalFixedMessage.PaymentHash, signingWallet.PrivateKey)
	if err != nil {
		return nil, err
	}
	signingPubKey := utils.SerializeCompressed(&signingWallet.PrivateKey.PublicKey)
	signatureResponse := types.GetPaymentSignatureResponse{
		Account:       signingWallet.XrpAddress,
		TxnSignature:  txnSignature,
		PaymentHash:   additionalFixedMessage.PaymentHash,
		SigningPubKey: signingPubKey,
	}

	responseBytes, err := json.Marshal(signatureResponse)
	if err != nil {
		return nil, err
	}

	return responseBytes, nil
}
