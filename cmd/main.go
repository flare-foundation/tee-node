package main

import (
	"github.com/flare-foundation/tee-node/internal/attestation"
	"github.com/flare-foundation/tee-node/internal/router"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/wallets"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
)

func main() {
	teeNode, err := node.Initialize(node.ZeroState{})
	if err != nil {
		logger.Fatalf("failed to initialize: %v", err)
	}
	ws := wallets.InitializeStorage()
	ps := policy.InitializeStorage()

	err = attestation.SetGoogleCert()
	if err != nil {
		logger.Fatalf("failed to load certificate: %v", err)
	}
	// err = attestation.SelfAttest()
	// if err != nil {
	// 	logger.Fatalf("self attestation failed: %v", err)
	// }

	go settings.ProxyURLConfigServer(settings.ProxyConfigureServerPort)

	r := router.NewPMWRouter(teeNode, ps, ws)

	// Launch the json rpc server
	r.Run(teeNode)
}
