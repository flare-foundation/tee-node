package types

import (
	"github.com/flare-foundation/go-flare-common/pkg/tee/constants"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
)

func ParsePaymentInstruction(data *instruction.DataFixed) (payment.ITeePaymentsPaymentInstructionMessage, error) {
	arg := payment.MessageArguments[constants.Pay]

	var instruction payment.ITeePaymentsPaymentInstructionMessage
	err := structs.DecodeTo(arg, data.OriginalMessage, &instruction)
	if err != nil {
		return payment.ITeePaymentsPaymentInstructionMessage{}, err
	}

	return instruction, nil
}
