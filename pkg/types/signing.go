package types

import (
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
)

// ParsePaymentInstruction decodes the payment instruction payload into the XRPL
// struct representation.
func ParsePaymentInstruction(data *instruction.DataFixed) (payment.ITeePaymentsPaymentInstructionMessage, error) {
	arg := payment.MessageArguments[op.Pay]

	var instruction payment.ITeePaymentsPaymentInstructionMessage
	err := structs.DecodeTo(arg, data.OriginalMessage, &instruction)
	if err != nil {
		return payment.ITeePaymentsPaymentInstructionMessage{}, err
	}

	return instruction, nil
}

type XRPSignResponse []map[string]any
