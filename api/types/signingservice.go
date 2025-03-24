package types

import (
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	commonpayment "github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
)

type SignPaymentAdditionalFixedMessage struct {
	PaymentHash string
	KeyId       string
}

func ParseSignPaymentRequest(instructionData *instruction.DataFixed) (commonpayment.ITeePaymentsPaymentInstructionMessage, error) {
	arg := commonpayment.MessageArguments[commonpayment.Pay]

	var signPaymentRequest commonpayment.ITeePaymentsPaymentInstructionMessage
	err := structs.DecodeTo(arg, instructionData.OriginalMessage, &signPaymentRequest)
	if err != nil {
		return commonpayment.ITeePaymentsPaymentInstructionMessage{}, err
	}

	return signPaymentRequest, nil
}

type SignPaymentResponse struct {
	ResponseBase
	Finalized bool
}

type GetPaymentSignatureResponse struct {
	PaymentHash   string
	TxnSignature  []byte
	SigningPubKey []byte
	Account       string
}
