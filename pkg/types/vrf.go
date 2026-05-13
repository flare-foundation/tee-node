package types

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	vrfstruct "github.com/flare-foundation/go-flare-common/pkg/tee/structs/vrf"
	walletsvrf "github.com/flare-foundation/tee-node/pkg/wallets/vrf"
)

// ParseVRFInstruction decodes the VRF instruction payload into the shared
// go-flare-common struct representation.
func ParseVRFInstruction(data *instruction.DataFixed) (vrfstruct.IVrfVrfInstructionMessage, error) {
	arg := vrfstruct.MessageArguments[op.VRF]

	var inst vrfstruct.IVrfVrfInstructionMessage
	err := structs.DecodeTo(arg, data.OriginalMessage, &inst)
	if err != nil {
		return vrfstruct.IVrfVrfInstructionMessage{}, err
	}

	return inst, nil
}

type ProveRandomnessResponse struct {
	WalletID common.Hash      `json:"walletId"`
	KeyID    uint64           `json:"keyId"`
	Nonce    hexutil.Bytes    `json:"nonce"`
	Proof    walletsvrf.Proof `json:"proof"`
}
