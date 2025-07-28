package server

import (
	"math/big"

	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/processor"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/types"
)

func StartServer() {
	err := node.InitNode(types.State{Status: big.NewInt(0)})
	if err != nil {
		panic(err)
	}
	go settings.ProxyUrlConfigServer()

	processor.RunTeeProcessor()
}
