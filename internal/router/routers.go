package router

import (
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/tee-node/internal/processors/direct"
	"github.com/flare-foundation/tee-node/internal/processors/direct/getutils"
	"github.com/flare-foundation/tee-node/internal/processors/direct/policyutils"
	"github.com/flare-foundation/tee-node/internal/processors/instructions"
	"github.com/flare-foundation/tee-node/internal/processors/instructions/fdcutils"
	"github.com/flare-foundation/tee-node/internal/processors/instructions/regutils"
	"github.com/flare-foundation/tee-node/internal/processors/instructions/signutils"
	"github.com/flare-foundation/tee-node/internal/processors/instructions/vrfutils"
	"github.com/flare-foundation/tee-node/internal/processors/instructions/walletutils"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/wallets"

	pnode "github.com/flare-foundation/tee-node/pkg/node"
)

// NewPMWRouter wires direct and instruction processors for the Protocol Managed
// Wallet service, without the extension defaults.
func NewPMWRouter(teeNode *pnode.Node, wStorage *wallets.Storage, pStorage *policy.Storage, proxyURL *settings.ProxyURLMutex) Router {
	r := New(proxyURL)

	gp := getutils.NewProcessor(teeNode, pStorage, wStorage)
	r.RegisterDirectProcessor(op.Get, op.KeyInfo, gp.KeysInfo)
	r.RegisterDirectProcessor(op.Get, op.KeyProof, gp.KeysProof)
	r.RegisterDirectProcessor(op.Get, op.TEEInfo, gp.TEEInfo)
	r.RegisterDirectProcessor(op.Get, op.TEEBackup, gp.TEEBackup)

	pp := policyutils.NewProcessor(pStorage)
	r.RegisterDirectProcessor(op.Policy, op.InitializePolicy, pp.InitializePolicy)
	r.RegisterDirectProcessor(op.Policy, op.UpdatePolicy, pp.UpdatePolicy)

	wp := walletutils.NewProcessor(teeNode, pStorage, wStorage)

	r.RegisterInstructionProcessor(op.Wallet, op.KeyGenerate, instructions.NewProcessor(wp.KeyGenerate, teeNode, pStorage, true))
	r.RegisterInstructionProcessor(op.Wallet, op.KeyDelete, instructions.NewProcessor(wp.KeyDelete, teeNode, pStorage, true))
	r.RegisterInstructionProcessor(op.Wallet, op.KeyDataProviderRestore, instructions.NewProcessor(wp.KeyDataProviderRestore, teeNode, pStorage, true))

	rp := regutils.NewProcessor(teeNode, pStorage)
	r.RegisterInstructionProcessor(op.Reg, op.TEEAttestation, instructions.NewProcessor(rp.TEEAttestation, teeNode, pStorage, true))

	ftp := fdcutils.NewProcessor(teeNode)
	r.RegisterInstructionProcessor(op.FDC2, op.Prove, instructions.NewProcessor(ftp.Prove, teeNode, pStorage, true))

	sp := signutils.NewProcessor(teeNode, wStorage, proxyURL)
	r.RegisterInstructionProcessor(op.XRP, op.Pay, instructions.NewProcessor(sp.SignXRPLPayment, teeNode, pStorage, false))
	r.RegisterInstructionProcessor(op.XRP, op.Reissue, instructions.NewProcessor(sp.SignXRPLPayment, teeNode, pStorage, false))

	vp := vrfutils.NewProcessor(teeNode, wStorage)
	r.RegisterInstructionProcessor(op.Wallet, op.VRF, instructions.NewProcessor(vp.ProveRandomness, teeNode, pStorage, true))

	return r
}

// NewForwardRouter assembles a router that manages base actions and
// forwards remaining actions to the external extension service.
func NewForwardRouter(teeNode *pnode.Node, wStorage *wallets.Storage, pStorage *policy.Storage, extensionPort int, proxyURL *settings.ProxyURLMutex) Router {
	r := New(proxyURL)

	gp := getutils.NewProcessor(teeNode, pStorage, wStorage)
	r.RegisterDirectProcessor(op.Get, op.KeyInfo, gp.KeysInfo)
	r.RegisterDirectProcessor(op.Get, op.KeyProof, gp.KeysProof)
	r.RegisterDirectProcessor(op.Get, op.TEEInfo, gp.TEEInfo)
	r.RegisterDirectProcessor(op.Get, op.TEEBackup, gp.TEEBackup)

	pp := policyutils.NewProcessor(pStorage)
	r.RegisterDirectProcessor(op.Policy, op.InitializePolicy, pp.InitializePolicy)
	r.RegisterDirectProcessor(op.Policy, op.UpdatePolicy, pp.UpdatePolicy)

	wp := walletutils.NewProcessor(teeNode, pStorage, wStorage)
	r.RegisterInstructionProcessor(op.Wallet, op.KeyGenerate, instructions.NewProcessor(wp.KeyGenerate, teeNode, pStorage, true))
	r.RegisterInstructionProcessor(op.Wallet, op.KeyDelete, instructions.NewProcessor(wp.KeyDelete, teeNode, pStorage, true))
	r.RegisterInstructionProcessor(op.Wallet, op.KeyDataProviderRestore, instructions.NewProcessor(wp.KeyDataProviderRestore, teeNode, pStorage, true))

	rp := regutils.NewProcessor(teeNode, pStorage)
	r.RegisterInstructionProcessor(op.Reg, op.TEEAttestation, instructions.NewProcessor(rp.TEEAttestation, teeNode, pStorage, true))

	defInst := instructions.NewDefaultProcessor(extensionPort, pStorage, teeNode)
	r.RegisterDefaultInstruction(defInst)

	defDirect := direct.NewDefaultProcessor(extensionPort)
	r.RegisterDefaultDirect(defDirect)

	return r
}
