package server

import (
	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/processor"
	"github.com/flare-foundation/tee-node/internal/settings"
)

func StartServer() {
	err := node.InitNode(node.ZeroState{})
	if err != nil {
		panic(err)
	}
	go settings.ProxyUrlConfigServer()

	processor.RunTeeProcessor()
}
