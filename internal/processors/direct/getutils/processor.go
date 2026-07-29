package getutils

import (
	"context"
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
	csigning "github.com/flare-foundation/go-flare-common/pkg/signing"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/internal/attestation"
	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/policy"
	"github.com/flare-foundation/tee-node/internal/wallets/backup"
	"github.com/flare-foundation/tee-node/pkg/types"

	walletstorage "github.com/flare-foundation/tee-node/internal/wallets"
	wallets "github.com/flare-foundation/tee-node/pkg/wallets"
)

type Processor struct {
	node.InformerAndSigner
	pStorage *policy.Storage
	wStorage *walletstorage.Storage
}

// NewProcessor builds a direct processor that serves TEE metadata and wallet
// information.
func NewProcessor(aAndS node.InformerAndSigner, policyStorage *policy.Storage, walletsStorage *walletstorage.Storage) Processor {
	return Processor{
		InformerAndSigner: aAndS,
		pStorage:          policyStorage,
		wStorage:          walletsStorage,
	}
}

// TEEInfo returns the TEE info response associated with the given challenge.
func (p *Processor) TEEInfo(_ context.Context, i *types.DirectInstruction) ([]byte, error) {
	var req types.TeeInfoRequest
	err := json.Unmarshal(i.Message, &req)
	if err != nil {
		return nil, err
	}

	// return even if not all is set
	info := p.Info()

	p.pStorage.RLock()
	initialID, initialHash, activeID, activeHash := p.pStorage.Info()
	p.pStorage.RUnlock()

	response, err := attestation.ConstructTEEInfoResponse(req.Challenge, &info, initialID, initialHash, activeID, activeHash)
	if err != nil {
		return nil, err
	}

	mdDataHash, err := response.MachineData.DataHash()
	if err != nil {
		return nil, err
	}
	mdHash, err := csigning.NewPayload(csigning.TEEMachineRegister, info.ChainID, mdDataHash).Hash()
	if err != nil {
		return nil, err
	}

	mdSignature, err := p.Sign(mdHash[:])
	if err != nil {
		return nil, err
	}
	response.DataSignature = mdSignature

	resultEncoded, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}

	return resultEncoded, nil
}

// KeysInfo lists the (walletID, keyID, nonce) triples of all stored wallets.
func (p *Processor) KeysInfo(_ context.Context, _ *types.DirectInstruction) ([]byte, error) {
	p.wStorage.RLock()
	storedWallets := p.wStorage.GetWallets()
	p.wStorage.RUnlock()

	infos := make([]types.KeyInfo, len(storedWallets))
	for i, storedWallet := range storedWallets {
		infos[i] = types.KeyInfo{
			WalletID: storedWallet.WalletID,
			KeyID:    storedWallet.KeyID,
			Nonce:    storedWallet.Status.Nonce,
		}
	}

	res, err := json.Marshal(infos)
	if err != nil {
		return nil, err
	}

	return res, nil
}

// KeysProof returns signed key existence proofs for the requested (walletID, keyID) pairs.
// Proofs are returned in the same order as the requested pairs.
func (p *Processor) KeysProof(ctx context.Context, i *types.DirectInstruction) ([]byte, error) {
	var requested []wallets.KeyIDPair
	if err := json.Unmarshal(i.Message, &requested); err != nil {
		return nil, err
	}

	info := p.Info()
	teeID := info.TeeID
	chainID := info.ChainID

	// Build the proof payloads (encoding and hashing read wallet state) under
	// the read lock, then release it before the per-element ECDSA signing,
	// since signing is the dominant cost.
	type pendingProof struct {
		encoded []byte
		hash    common.Hash
	}
	pending := make([]pendingProof, len(requested))

	p.wStorage.RLock()
	for idx, idPair := range requested {
		storedWallet, err := p.wStorage.Get(idPair)
		if err != nil {
			p.wStorage.RUnlock()
			return nil, err
		}

		ep := storedWallet.KeyExistenceProof(teeID)
		epEncoded, err := structs.Encode(wallet.KeyExistenceStructArg, ep)
		if err != nil {
			p.wStorage.RUnlock()
			return nil, err
		}
		dataHash, err := types.KeyExistenceDataHash(ep)
		if err != nil {
			p.wStorage.RUnlock()
			return nil, err
		}
		hash, err := csigning.NewPayload(csigning.TEEKeyExistence, chainID, dataHash).Hash()
		if err != nil {
			p.wStorage.RUnlock()
			return nil, err
		}

		pending[idx] = pendingProof{encoded: epEncoded, hash: hash}
	}
	p.wStorage.RUnlock()

	signedProofs := make([]wallets.SignedKeyExistenceProof, len(requested))
	for idx, pp := range pending {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		signature, err := p.Sign(pp.hash.Bytes())
		if err != nil {
			return nil, err
		}
		signedProofs[idx] = wallets.SignedKeyExistenceProof{
			KeyExistence: pp.encoded,
			Signature:    signature,
		}
	}

	res, err := json.Marshal(signedProofs)
	if err != nil {
		return nil, err
	}

	return res, nil
}

// TEEBackup produces a TEE-signed backup package for the requested wallet key.
func (p *Processor) TEEBackup(_ context.Context, i *types.DirectInstruction) ([]byte, error) {
	var idPair wallets.KeyIDPair
	err := json.Unmarshal(i.Message, &idPair)
	if err != nil {
		return nil, err
	}
	info := p.Info()
	teeID := info.TeeID
	chainID := info.ChainID

	p.wStorage.RLock()
	defer p.wStorage.RUnlock()

	wallet, err := p.wStorage.Get(idPair)
	if err != nil {
		return nil, err
	}

	p.pStorage.RLock()
	activePolicy, err := p.pStorage.ActiveSigningPolicy()
	if err != nil {
		p.pStorage.RUnlock()
		return nil, err
	}
	activePolicyPublicKeys, err := p.pStorage.ActiveSigningPolicyPublicKeys()
	p.pStorage.RUnlock()
	if err != nil {
		return nil, err
	}

	weights := make([]uint16, len(activePolicy.Voters.Voters()))
	for i := range activePolicy.Voters.Voters() {
		weights[i] = activePolicy.Voters.VoterWeight(i)
	}

	walletBackup, err := backup.BackupWallet(
		wallet,
		activePolicyPublicKeys,
		weights,
		activePolicy.RewardEpochID,
		teeID,
		chainID,
		backup.NormalizationConstant,
		backup.DataProvidersThreshold,
	)
	if err != nil {
		return nil, err
	}
	signHash, err := walletBackup.TEESignHash(chainID)
	if err != nil {
		return nil, err
	}
	walletBackup.TEESignature, err = p.Sign(signHash[:])
	if err != nil {
		return nil, err
	}

	walletBackupBytes, err := json.Marshal(walletBackup)
	if err != nil {
		return nil, err
	}

	res, err := json.Marshal(
		wallets.TEEBackupResponse{WalletBackup: walletBackupBytes, BackupID: walletBackup.WalletBackupID},
	)
	if err != nil {
		return nil, err
	}

	return res, nil
}
