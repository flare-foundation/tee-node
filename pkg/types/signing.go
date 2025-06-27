package types

import (
	"github.com/flare-foundation/go-flare-common/pkg/tee/constants"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
)

type SignPaymentAdditionalFixedMessage struct {
	PaymentHash string
	KeyId       uint64
}

func ParseSignPaymentRequest(instructionData *instruction.DataFixed) (payment.ITeePaymentsPaymentInstructionMessage, error) {
	arg := payment.MessageArguments[constants.Pay]

	var signPaymentRequest payment.ITeePaymentsPaymentInstructionMessage
	err := structs.DecodeTo(arg, instructionData.OriginalMessage, &signPaymentRequest)
	if err != nil {
		return payment.ITeePaymentsPaymentInstructionMessage{}, err
	}

	return signPaymentRequest, nil
}

type GetPaymentSignatureResponse struct {
	PaymentHash   string
	TxnSignature  []byte
	SigningPubKey []byte
	Account       string
}
