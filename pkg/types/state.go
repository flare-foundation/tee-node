package types

// Todo: This is where an extension would define its state and any logic to use it!

import (
	"math/big"

	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/tee"
)

type State struct {
	Status *big.Int
}

// Todo: this should just be moved to go-flare-common
func (s State) Encode() ([]byte, error) {
	state := tee.TeeStructsPMWState{
		Status: s.Status,
	}

	enc, err := structs.Encode(tee.StructArg[tee.PMWState], state)
	if err != nil {
		return nil, err
	}

	return enc, nil
}
