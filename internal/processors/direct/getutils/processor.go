package getutils

import (
	"encoding/json"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/internal/attestation"
	"github.com/flare-foundation/tee-node/internal/wallets/backup"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/types"

	"github.com/flare-foundation/tee-node/pkg/wallets"
)

type Processor struct {
	node.InformerAndSigner
	pStorage *policy.Storage
	wStorage *wallets.Storage
}

// NewProcessor builds a direct processor that serves TEE metadata and wallet
// information.
func NewProcessor(aAndS node.InformerAndSigner, policyStorage *policy.Storage, walletsStorage *wallets.Storage) Processor {
	return Processor{
		InformerAndSigner: aAndS,
		pStorage:          policyStorage,
		wStorage:          walletsStorage,
	}
}

// TEEInfo returns the TEE info response associated with the given challenge.
func (p *Processor) TEEInfo(i *types.DirectInstruction) ([]byte, error) {
	var req types.TeeInfoRequest
	err := json.Unmarshal(i.Message, &req)
	if err != nil {
		return nil, err
	}

	info := p.Info()

	p.pStorage.RLock()
	initialID, initialHash, activeID, activeHash := p.pStorage.Info()
	p.pStorage.RUnlock()

	response, err := attestation.ConstructTEEInfoResponse(req.Challenge, &info, initialID, initialHash, activeID, activeHash)
	if err != nil {
		return nil, err
	}

	mdHash, err := response.MachineData.Hash()
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

// KeysInfo lists the stored wallets as signed existence proofs.
func (p *Processor) KeysInfo(_ *types.DirectInstruction) ([]byte, error) {
	teeID := p.Info().TeeID

	storedWallets := p.wStorage.GetWallets()

	signedProofs := make([]wallets.SignedKeyExistenceProof, len(storedWallets))
	for i, storedWallet := range storedWallets {
		ep := storedWallet.KeyExistenceProof(teeID)
		epEncoded, err := structs.Encode(wallet.KeyExistenceStructArg, ep)
		if err != nil {
			return nil, err
		}
		hash := crypto.Keccak256(epEncoded)
		signature, err := p.Sign(hash)
		if err != nil {
			return nil, err
		}

		signedProofs[i] = wallets.SignedKeyExistenceProof{
			KeyExistence: epEncoded,
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
func (p *Processor) TEEBackup(i *types.DirectInstruction) ([]byte, error) {
	var idPair wallets.KeyIDPair
	err := json.Unmarshal(i.Message, &idPair)
	if err != nil {
		return nil, err
	}
	teeID := p.Info().TeeID

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
		backup.NormalizationConstant,
		backup.DataProvidersThreshold,
	)
	if err != nil {
		return nil, err
	}
	hash, err := walletBackup.HashForSigning()
	if err != nil {
		return nil, err
	}
	walletBackup.TEESignature, err = p.Sign(hash[:])
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
