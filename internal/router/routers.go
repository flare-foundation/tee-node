package router

import (
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/tee-node/internal/processors/direct"
	"github.com/flare-foundation/tee-node/internal/processors/direct/getutils"
	"github.com/flare-foundation/tee-node/internal/processors/direct/policyutils"
	"github.com/flare-foundation/tee-node/internal/processors/instructions"
	"github.com/flare-foundation/tee-node/internal/processors/instructions/ftdcutils"
	"github.com/flare-foundation/tee-node/internal/processors/instructions/regutils"
	"github.com/flare-foundation/tee-node/internal/processors/instructions/signutils"
	"github.com/flare-foundation/tee-node/internal/processors/instructions/walletutils"
	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/wallets"

	pnode "github.com/flare-foundation/tee-node/pkg/node"
)

func NewPMWRouter(teeNode *pnode.Node, pStorage *policy.Storage, wStorage *wallets.Storage) Router {
	r := New()

	gp := getutils.NewProcessor(teeNode, pStorage, wStorage)
	r.RegisterDirectProcessor(op.Get, op.KeyInfo, gp.KeysInfo)
	r.RegisterDirectProcessor(op.Get, op.TEEInfo, gp.TEEInfo)
	r.RegisterDirectProcessor(op.Get, op.TEEBackup, gp.TEEBackup)

	pp := policyutils.NewProcessor(pStorage)
	r.RegisterDirectProcessor(op.Policy, op.InitializePolicy, pp.InitializePolicy)
	r.RegisterDirectProcessor(op.Policy, op.UpdatePolicy, pp.UpdatePolicy)

	wp := walletutils.NewProcessor(teeNode, pStorage, wStorage)
	r.RegisterInstructionProcessor(op.Wallet, op.KeyGenerate, instructions.NewProcessor(wp.KeyGenerate, teeNode, pStorage))
	r.RegisterInstructionProcessor(op.Wallet, op.KeyDelete, instructions.NewProcessor(wp.KeyDelete, teeNode, pStorage))
	r.RegisterInstructionProcessor(op.Wallet, op.KeyDataProviderRestore, instructions.NewProcessor(wp.KeyDataProviderRestore, teeNode, pStorage))

	rp := regutils.NewProcessor(teeNode, pStorage)
	r.RegisterInstructionProcessor(op.Reg, op.TEEAttestation, instructions.NewProcessor(rp.TEEAttestation, teeNode, pStorage))

	ftp := ftdcutils.NewProcessor(teeNode)
	r.RegisterInstructionProcessor(op.FTDC, op.Prove, instructions.NewProcessor(ftp.Prove, teeNode, pStorage))

	sp := signutils.NewProcessor(teeNode, wStorage)
	r.RegisterInstructionProcessor(op.XRP, op.Pay, instructions.NewProcessor(sp.SignXRPLPayment, teeNode, pStorage))
	r.RegisterInstructionProcessor(op.XRP, op.Reissue, instructions.NewProcessor(sp.SignXRPLPayment, teeNode, pStorage))

	return r
}

func NewExtensionRouter(teeNode *pnode.Node, pStorage *policy.Storage, wStorage *wallets.Storage, extensionPort int) Router {
	r := New()

	gp := getutils.NewProcessor(teeNode, pStorage, wStorage)
	r.RegisterDirectProcessor(op.Get, op.KeyInfo, gp.KeysInfo)
	r.RegisterDirectProcessor(op.Get, op.TEEInfo, gp.TEEInfo)
	r.RegisterDirectProcessor(op.Get, op.TEEBackup, gp.TEEBackup)

	pp := policyutils.NewProcessor(pStorage)
	r.RegisterDirectProcessor(op.Policy, op.InitializePolicy, pp.InitializePolicy)
	r.RegisterDirectProcessor(op.Policy, op.UpdatePolicy, pp.UpdatePolicy)

	wp := walletutils.NewProcessor(teeNode, pStorage, wStorage)
	r.RegisterInstructionProcessor(op.Wallet, op.KeyGenerate, instructions.NewProcessor(wp.KeyGenerate, teeNode, pStorage))
	r.RegisterInstructionProcessor(op.Wallet, op.KeyDelete, instructions.NewProcessor(wp.KeyDelete, teeNode, pStorage))
	r.RegisterInstructionProcessor(op.Wallet, op.KeyDataProviderRestore, instructions.NewProcessor(wp.KeyDataProviderRestore, teeNode, pStorage))

	rp := regutils.NewProcessor(teeNode, pStorage)
	r.RegisterInstructionProcessor(op.Reg, op.TEEAttestation, instructions.NewProcessor(rp.TEEAttestation, teeNode, pStorage))

	defInst := instructions.NewDefaultProcessor(extensionPort, pStorage, teeNode)
	r.RegisterDefaultInstruction(defInst)

	defDirect := direct.NewDefaultProcessor(extensionPort)
	r.RegisterDefaultDirect(defDirect)

	return r
}
