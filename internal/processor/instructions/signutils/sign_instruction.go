package signutils

import (
	"encoding/json"

	"github.com/flare-foundation/tee-node/internal/signing"
	"github.com/flare-foundation/tee-node/internal/wallets"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
)

func SignPaymentTransaction(instructionData *instruction.DataFixed, signers []common.Address, isSignerDataProvider []bool) ([]byte, error) {
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

	walletKeyIdPair := types.WalletKeyIdPair{WalletId: originalMessage.WalletId, KeyId: additionalFixedMessage.KeyId}
	wallets.Storage.RLock()
	signingWallet, err := wallets.Storage.GetWallet(walletKeyIdPair)
	wallets.Storage.RUnlock()
	if err != nil {
		return nil, err
	}

	_, err = utils.CheckCosigners(signers, isSignerDataProvider, signingWallet.Cosigners, signingWallet.CosignersThreshold)
	if err != nil {
		return nil, err
	}

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
