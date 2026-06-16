package walletutils

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	cpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/random"
	csigning "github.com/flare-foundation/go-flare-common/pkg/signing"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/machinepath"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/policy"
	walletstorage "github.com/flare-foundation/tee-node/internal/wallets"
	"github.com/flare-foundation/tee-node/internal/wallets/backup"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
	wallets "github.com/flare-foundation/tee-node/pkg/wallets"
	pkgbackup "github.com/flare-foundation/tee-node/pkg/wallets/backup"
)

type Processor struct {
	pStorage *policy.Storage
	wStorage *walletstorage.Storage
	node.WalletNode
}

// NewProcessor constructs the wallet utility processor with the storages and
// TEE capabilities it relies on.
func NewProcessor(walletNode node.WalletNode, policyStorage *policy.Storage, walletsStorage *walletstorage.Storage) Processor {
	return Processor{
		pStorage:   policyStorage,
		wStorage:   walletsStorage,
		WalletNode: walletNode,
	}
}

// KeyGenerate handles wallet key creation instructions, persisting the new key
// and returning a signed existence proof.
func (p *Processor) KeyGenerate(
	ctx context.Context,
	submissionTag types.SubmissionTag,
	dataFixed *instruction.DataFixed,
	_ []hexutil.Bytes,
	_ []common.Address,
	_ *cpolicy.SigningPolicy,
) ([]byte, []byte, error) {
	req, err := wallets.ParseKeyGenerate(dataFixed)
	if err != nil {
		return nil, nil, err
	}

	err = wallets.CheckKeyGenerate(req, p.TeeID())
	if err != nil {
		return nil, nil, err
	}

	p.wStorage.Lock()
	defer p.wStorage.Unlock()

	keyIDPair := wallets.KeyIDPair{WalletID: req.WalletId, KeyID: req.KeyId}

	if submissionTag == types.Threshold {
		if p.wStorage.WalletExistsPermanent(keyIDPair) {
			return nil, nil, errors.New("a permanent record of the wallet already exists")
		}

		key, err := wallets.GenerateNewKey(req)
		if err != nil {
			return nil, nil, err
		}

		// timeout check before changing state
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		err = p.wStorage.Store(key)
		if err != nil {
			return nil, nil, err
		}
	}
	storedWallet, err := p.wStorage.Get(keyIDPair)
	if err != nil {
		return nil, nil, err
	}

	existenceProof := storedWallet.KeyExistenceProof(p.TeeID())
	existenceProofEncoded, err := structs.Encode(wallet.KeyExistenceStructArg, existenceProof)
	if err != nil {
		return nil, nil, err
	}

	chainID, err := p.ChainID()
	if err != nil {
		return nil, nil, err
	}
	dataHash, err := types.KeyExistenceDataHash(existenceProof)
	if err != nil {
		return nil, nil, err
	}
	hash, err := csigning.NewPayload(csigning.TEEKeyExistence, chainID, dataHash).Hash()
	if err != nil {
		return nil, nil, err
	}
	signature, err := p.Sign(hash[:])
	if err != nil {
		return nil, nil, err
	}

	signedProof := wallets.SignedKeyExistenceProof{
		KeyExistence: existenceProofEncoded,
		Signature:    signature,
	}

	resultEncoded, err := json.Marshal(signedProof)
	if err != nil {
		return nil, nil, err
	}

	return resultEncoded, nil, nil
}

// KeyDelete processes key removal instructions and enforces nonce-based replay
// protection.
func (p *Processor) KeyDelete(
	ctx context.Context,
	submissionTag types.SubmissionTag,
	dataFixed *instruction.DataFixed,
	_ []hexutil.Bytes,
	_ []common.Address,
	_ *cpolicy.SigningPolicy,
) ([]byte, []byte, error) {
	req, err := wallets.ParseKeyDelete(dataFixed)
	if err != nil {
		return nil, nil, err
	}
	if !req.Nonce.IsUint64() {
		return nil, nil, errors.New("nonce too large")
	}

	p.wStorage.Lock()
	defer p.wStorage.Unlock()

	id := wallets.KeyIDPair{WalletID: req.WalletId, KeyID: req.KeyId}

	if !p.wStorage.WalletExistsPermanent(id) {
		return nil, nil, errors.New("wallet never existed")
	}

	switch submissionTag {
	case types.Threshold:
		err = p.wStorage.CheckNonce(id, req.Nonce.Uint64())
		if err != nil {
			return nil, nil, err
		}

		var additionalResultStatus []byte

		exists := p.wStorage.WalletExists(id)
		if !exists {
			additionalResultStatus = []byte("key not stored")
		}
		// timeout check before changing state
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		p.wStorage.Remove(id)
		p.wStorage.UpdateNonce(id, req.Nonce.Uint64())

		encodedID, err := json.Marshal(id)

		return encodedID, additionalResultStatus, err

	case types.End:
		exists := p.wStorage.WalletExists(id)
		if exists {
			return nil, nil, errors.New("wallet not deleted, still exists")
		}

		err = p.wStorage.CheckNonce(id, req.Nonce.Uint64())
		if err == nil {
			return nil, nil, errors.New("nonce not used")
		}

	default:
		return nil, nil, errors.New("unexpected submission tag")
	}

	return nil, nil, nil
}

// KeyDataProviderRestore reconstructs a wallet key from provider shares and
// emits a signed existence proof when successful.
func (p *Processor) KeyDataProviderRestore(
	ctx context.Context,
	submissionTag types.SubmissionTag,
	dataFixed *instruction.DataFixed,
	variableMessages []hexutil.Bytes,
	signers []common.Address,
	_ *cpolicy.SigningPolicy,
) ([]byte, []byte, error) {
	metadata, nonce, signersBothRoles, err := p.keyRestoreDataCheck(dataFixed, signers, p.TeeID())
	if err != nil {
		return nil, nil, err
	}

	backupID := metadata.WalletBackupID
	id := wallets.KeyIDPair{WalletID: backupID.WalletID, KeyID: backupID.KeyID}

	keySplits, status, err := p.processKeySplitMessages(variableMessages, signersBothRoles, backupID)
	if err != nil {
		return nil, nil, err
	}
	// An error beyond this check implies that ether the shares are not sufficient,
	// or that the shares have been tampered while still having valid signatures and matching id,
	// the latter implying that the key has been compromised

	recoveredWallet, err := backup.RecoverWallet(keySplits, metadata)
	if err != nil {
		return nil, status, err
	}

	p.wStorage.Lock()
	defer p.wStorage.Unlock()

	switch submissionTag {
	case types.Threshold:
		if p.wStorage.WalletExists(id) {
			return nil, nil, errors.New("wallet with given wallet-key id already exists")
		}
		if p.wStorage.WalletExistsPermanent(id) {
			err = p.wStorage.CheckNonce(id, nonce)
			if err != nil {
				return nil, nil, err
			}
		}

		// timeout check before changing state
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		err = p.wStorage.Store(recoveredWallet)
		if err != nil {
			return nil, nil, err
		}
		p.wStorage.UpdateNonce(id, nonce)

		storedWallet, err := p.wStorage.Get(id)
		if err != nil {
			return nil, nil, err
		}

		ep := storedWallet.KeyExistenceProof(p.TeeID())
		existenceProofEncoded, err := structs.Encode(wallet.KeyExistenceStructArg, ep)
		if err != nil {
			return nil, nil, err
		}

		chainID, err := p.ChainID()
		if err != nil {
			return nil, nil, err
		}
		dataHash, err := types.KeyExistenceDataHash(ep)
		if err != nil {
			return nil, nil, err
		}
		hash, err := csigning.NewPayload(csigning.TEEKeyExistence, chainID, dataHash).Hash()
		if err != nil {
			return nil, nil, err
		}
		signature, err := p.Sign(hash[:])
		if err != nil {
			return nil, nil, errors.New("cannot sign existence proof")
		}

		wskep := wallets.SignedKeyExistenceProof{
			KeyExistence: existenceProofEncoded,
			Signature:    signature,
		}

		resultEncoded, err := json.Marshal(wskep)
		if err != nil {
			return nil, nil, err
		}

		return resultEncoded, status, nil

	case types.End:
		exists := p.wStorage.WalletExists(id)
		if !exists {
			return nil, nil, errors.New("wallet does not exists")
		}
		checkNonce, err := p.wStorage.Nonce(id)
		if err != nil {
			return nil, nil, err
		}
		if checkNonce != nonce {
			return nil, nil, errors.New("wallet nonce already changed")
		}

		return nil, status, nil

	default:
		return nil, nil, errors.New("unexpected submission tag")
	}
}

// pathAuthorizes reports whether any single machine path contains source
// on its source list and destination on its destination list.
func pathAuthorizes(paths []machinepath.IMachinePathManagerMachinePath, source, destination common.Address) bool {
	for _, p := range paths {
		if slices.Contains(p.SourceTeeIds, source) && slices.Contains(p.DestinationTeeIds, destination) {
			return true
		}
	}
	return false
}

// validateKeyDirectRestoreRequest authorizes a KEY_DIRECT_RESTORE
// request and returns the parsed destinationNonce. It requires
// BackupId.teeId to equal sourceTeeId, machinePathListNonce to fit in
// uint64 and not exceed the node's current value, the current path
// list to authorize the (source, this TEE) pair, and destinationNonce
// to fit in uint64.
func (p *Processor) validateKeyDirectRestoreRequest(
	req wallet.IWalletBackupManagerKeyDirectRestore,
) (uint64, error) {
	if req.BackupId.TeeId != req.SourceTeeId {
		return 0, errors.New("instruction BackupId.teeId does not match sourceTeeId")
	}
	if !req.MachinePathListNonce.IsUint64() {
		return 0, errors.New("machinePathListNonce too large")
	}
	machinePathListNonce := req.MachinePathListNonce.Uint64()
	paths, currentMachinePathListNonce := p.MachinePaths()
	if machinePathListNonce > currentMachinePathListNonce {
		return 0, fmt.Errorf("stale node state: instruction machine-path-list nonce %d above node's %d",
			machinePathListNonce, currentMachinePathListNonce)
	}
	if !pathAuthorizes(paths, req.SourceTeeId, p.TeeID()) {
		return 0, errors.New("no machine path authorizes this source TEE and this destination TEE")
	}
	if !req.DestinationNonce.IsUint64() {
		return 0, errors.New("destinationNonce too large")
	}
	return req.DestinationNonce.Uint64(), nil
}

// validateKeyDirectBackupRequest authorizes a KEY_DIRECT_BACKUP
// request and returns the parsed destination public key. It requires
// sourceTeeId to equal this TEE's identity, machinePathListNonce to
// fit in uint64 and equal the node's current value, the destination
// public key to parse, and the current path list to authorize the
// (this TEE, destination) pair.
func (p *Processor) validateKeyDirectBackupRequest(
	req wallet.IWalletBackupManagerKeyDirectBackup,
) (*ecdsa.PublicKey, error) {
	if req.SourceTeeId != p.TeeID() {
		return nil, errors.New("requested sourceTeeId does not match this TEE")
	}
	if !req.MachinePathListNonce.IsUint64() {
		return nil, errors.New("machinePathListNonce too large")
	}
	machinePathListNonce := req.MachinePathListNonce.Uint64()

	destinationPubKey, err := types.ParsePubKey(types.PublicKey{
		X: req.DestinationTeePublicKey.X,
		Y: req.DestinationTeePublicKey.Y,
	})
	if err != nil {
		return nil, err
	}
	destinationAddr := crypto.PubkeyToAddress(*destinationPubKey)

	paths, currentMachinePathListNonce := p.MachinePaths()
	if machinePathListNonce != currentMachinePathListNonce {
		return nil, fmt.Errorf("machine-path-list nonce mismatch: instruction %d, node %d",
			machinePathListNonce, currentMachinePathListNonce)
	}
	if !pathAuthorizes(paths, p.TeeID(), destinationAddr) {
		return nil, errors.New("no machine path authorizes this source and destination TEE")
	}
	return destinationPubKey, nil
}

// KeyDirectBackup ECIES-encrypts the wallet's private key for the
// destination's public key, embeds the ciphertext alongside the
// plaintext BackupID and wallet configuration in a payload, signs the
// payload with this TEE's identity key, and returns the envelope. The
// produced blob is stateless with respect to the destination's per-key
// nonce.
func (p *Processor) KeyDirectBackup(
	ctx context.Context,
	submissionTag types.SubmissionTag,
	dataFixed *instruction.DataFixed,
	_ []hexutil.Bytes,
	_ []common.Address,
	_ *cpolicy.SigningPolicy,
) ([]byte, []byte, error) {
	req, err := wallets.ParseKeyDirectBackup(dataFixed)
	if err != nil {
		return nil, nil, err
	}

	destinationPubKey, err := p.validateKeyDirectBackupRequest(req)
	if err != nil {
		return nil, nil, err
	}
	id := wallets.KeyIDPair{WalletID: req.WalletId, KeyID: req.KeyId}

	switch submissionTag {
	case types.Threshold:
		p.pStorage.RLock()
		activePolicy, err := p.pStorage.ActiveSigningPolicy()
		p.pStorage.RUnlock()
		if err != nil {
			return nil, nil, err
		}
		rewardEpochID := activePolicy.RewardEpochID

		randomNonce, err := random.Hash()
		if err != nil {
			return nil, nil, err
		}

		p.wStorage.RLock()
		w, err := p.wStorage.Get(id)
		p.wStorage.RUnlock()
		if err != nil {
			return nil, nil, err
		}
		// secp256k1 is required by both BackupID.PublicKey derivation
		// and the destination's ECIES decryption.
		if !slices.Contains(wallets.Algos, w.SigningAlgo) {
			return nil, nil, fmt.Errorf("unsupported signing algorithm: %s", w.SigningAlgo.Hex())
		}

		encryptedPrivateKey, err := utils.Encrypt(w.PrivateKey, destinationPubKey)
		if err != nil {
			return nil, nil, err
		}

		payload, err := pkgbackup.NewKeyDirectBackupPayload(w, p.TeeID(), encryptedPrivateKey, rewardEpochID, randomNonce)
		if err != nil {
			return nil, nil, err
		}
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, err
		}

		chainID, err := p.ChainID()
		if err != nil {
			return nil, nil, err
		}
		signHash, err := csigning.NewPayload(csigning.TEEKeyDirectBackup, chainID, crypto.Keccak256Hash(payloadBytes)).Hash()
		if err != nil {
			return nil, nil, err
		}
		signature, err := p.Sign(signHash[:])
		if err != nil {
			return nil, nil, err
		}

		envelopeBytes, err := json.Marshal(types.SignedKeyDirectBackup{
			Payload:      payloadBytes,
			TEESignature: signature,
		})
		if err != nil {
			return nil, nil, err
		}

		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		return envelopeBytes, nil, nil

	case types.End:
		p.wStorage.RLock()
		exists := p.wStorage.WalletExists(id)
		p.wStorage.RUnlock()
		if !exists {
			return nil, nil, errors.New("wallet does not exist")
		}
		return nil, nil, nil

	default:
		return nil, nil, errors.New("unexpected submission tag")
	}
}

// KeyDirectRestore verifies the source TEE's signature over the
// payload carried in dataFixed.AdditionalFixedMessage, cross-checks
// the payload's BackupID against the quorum-signed BackupId in the
// instruction, ECIES-decrypts the embedded private key, and stores
// the wallet locally. The request is rejected if the (source, this
// TEE) pair is not authorized by the current machine-path list, if
// the instruction's machine-path-list nonce is above the node's, or
// if the BackupID's reward epoch falls outside {current, current+1}.
func (p *Processor) KeyDirectRestore(
	ctx context.Context,
	submissionTag types.SubmissionTag,
	dataFixed *instruction.DataFixed,
	_ []hexutil.Bytes,
	_ []common.Address,
	_ *cpolicy.SigningPolicy,
) ([]byte, []byte, error) {
	req, err := wallets.ParseKeyDirectRestore(dataFixed)
	if err != nil {
		return nil, nil, err
	}

	destinationNonce, err := p.validateKeyDirectRestoreRequest(req)
	if err != nil {
		return nil, nil, err
	}

	p.pStorage.RLock()
	activePolicy, err := p.pStorage.ActiveSigningPolicy()
	p.pStorage.RUnlock()
	if err != nil {
		return nil, nil, err
	}
	currentRewardEpoch := activePolicy.RewardEpochID

	walletID := common.Hash(req.BackupId.WalletId)
	id := wallets.KeyIDPair{WalletID: walletID, KeyID: req.BackupId.KeyId}

	if len(dataFixed.AdditionalFixedMessage) == 0 {
		return nil, nil, errors.New("backup envelope missing")
	}

	var envelope types.SignedKeyDirectBackup
	if err := json.Unmarshal(dataFixed.AdditionalFixedMessage, &envelope); err != nil {
		return nil, nil, err
	}
	chainID, err := p.ChainID()
	if err != nil {
		return nil, nil, err
	}
	envelopeSignHash, err := csigning.NewPayload(csigning.TEEKeyDirectBackup, chainID, crypto.Keccak256Hash(envelope.Payload)).Hash()
	if err != nil {
		return nil, nil, err
	}
	if err := utils.VerifySignature(envelopeSignHash[:], envelope.TEESignature, req.SourceTeeId); err != nil {
		return nil, nil, err
	}

	var payload pkgbackup.KeyDirectBackupPayload
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		return nil, nil, err
	}
	if err := matchesInstructionBackupId(&payload.BackupID, &req.BackupId); err != nil {
		return nil, nil, err
	}

	if currentRewardEpoch != payload.BackupID.RewardEpochID &&
		currentRewardEpoch != payload.BackupID.RewardEpochID+1 {
		return nil, nil, fmt.Errorf("stale backup: reward epoch %d not in {%d, %d}",
			currentRewardEpoch, payload.BackupID.RewardEpochID, payload.BackupID.RewardEpochID+1)
	}

	privateKey, err := p.Decrypt(payload.EncryptedPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	restored, err := pkgbackup.WalletFromKeyDirectBackupPayload(&payload, privateKey)
	if err != nil {
		return nil, nil, err
	}

	p.wStorage.Lock()
	defer p.wStorage.Unlock()

	switch submissionTag {
	case types.Threshold:
		if p.wStorage.WalletExists(id) {
			return nil, nil, errors.New("wallet with given wallet-key id already exists")
		}
		if p.wStorage.WalletExistsPermanent(id) {
			if err := p.wStorage.CheckNonce(id, destinationNonce); err != nil {
				return nil, nil, err
			}
		}

		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if err := p.wStorage.Store(restored); err != nil {
			return nil, nil, err
		}
		p.wStorage.UpdateNonce(id, destinationNonce)

		storedWallet, err := p.wStorage.Get(id)
		if err != nil {
			return nil, nil, err
		}
		ep := storedWallet.KeyExistenceProof(p.TeeID())
		epEncoded, err := structs.Encode(wallet.KeyExistenceStructArg, ep)
		if err != nil {
			return nil, nil, err
		}
		chainID, err := p.ChainID()
		if err != nil {
			return nil, nil, err
		}
		dataHash, err := types.KeyExistenceDataHash(ep)
		if err != nil {
			return nil, nil, err
		}
		hash, err := csigning.NewPayload(csigning.TEEKeyExistence, chainID, dataHash).Hash()
		if err != nil {
			return nil, nil, err
		}
		signature, err := p.Sign(hash[:])
		if err != nil {
			return nil, nil, errors.New("cannot sign existence proof")
		}
		resultEncoded, err := json.Marshal(wallets.SignedKeyExistenceProof{
			KeyExistence: epEncoded,
			Signature:    signature,
		})
		if err != nil {
			return nil, nil, err
		}
		return resultEncoded, nil, nil

	case types.End:
		if !p.wStorage.WalletExists(id) {
			return nil, nil, errors.New("wallet does not exist")
		}
		checkNonce, err := p.wStorage.Nonce(id)
		if err != nil {
			return nil, nil, err
		}
		if checkNonce != destinationNonce {
			return nil, nil, errors.New("wallet nonce already changed")
		}
		return nil, nil, nil

	default:
		return nil, nil, errors.New("unexpected submission tag")
	}
}

// matchesInstructionBackupId verifies that the source-signed payload's
// BackupID matches the quorum-signed BackupId carried in the
// instruction, comparing the canonical ABI encoding rather than
// individual fields.
func matchesInstructionBackupId(payloadID *wallets.WalletBackupID, instructionID *wallet.IWalletBackupManagerBackupId) error {
	rebuilt := &wallets.WalletBackupID{
		TeeID:         instructionID.TeeId,
		WalletID:      instructionID.WalletId,
		KeyID:         instructionID.KeyId,
		PublicKey:     append(hexutil.Bytes(nil), instructionID.PublicKey...),
		KeyType:       instructionID.KeyType,
		SigningAlgo:   instructionID.SigningAlgo,
		RewardEpochID: instructionID.RewardEpochId,
		RandomNonce:   instructionID.RandomNonce,
	}
	if err := payloadID.Equal(rebuilt); err != nil {
		return fmt.Errorf("payload BackupID does not match instruction BackupId: %w", err)
	}
	return nil
}
