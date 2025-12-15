package walletutils

import (
	"encoding/json"
	"errors"
	"slices"

	pkgbackup "github.com/flare-foundation/tee-node/pkg/wallets/backup"

	"github.com/flare-foundation/tee-node/pkg/processorutils"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
	"github.com/flare-foundation/tee-node/pkg/wallets"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
)

// keyRestoreDataCheck checks the following thing:
//
//   - the teeID in the instruction data matches the teeID of the current TEE
//   - the signing algorithm is supported
//   - the wallet backup ID in the metadata matches the ID in the instruction data
//   - the cosigners and cosigner threshold stated in the instruction match the admin addresses admin threshold in backup data
//   - the admin threshold is met,
//
// and returns backup metadata, action nonce, slice of indicator of signers that are both data providers and admins, and error.
func (p *Processor) keyRestoreDataCheck(
	instructionData *instruction.DataFixed,
	signers []common.Address,
	teeID common.Address,
) (*pkgbackup.WalletBackupMetaData, uint64, []bool, error) {
	restoreRequest, err := wallets.ParseKeyDataProviderRestore(instructionData)
	if err != nil {
		return nil, 0, nil, err
	}

	teePubKey, err := types.ParsePubKey(types.PublicKey{
		X: restoreRequest.TeePublicKey.X,
		Y: restoreRequest.TeePublicKey.Y,
	})
	if err != nil {
		return nil, 0, nil, err
	}
	if crypto.PubkeyToAddress(*teePubKey) != teeID {
		return nil, 0, nil, errors.New("teeID does not match given public key")
	}
	if !slices.Contains(wallets.SigningAlgos, restoreRequest.BackupId.SigningAlgo) {
		return nil, 0, nil, errors.New("signing algorithm not supported")
	}

	var backupMetadata pkgbackup.WalletBackupMetaData
	err = json.Unmarshal(instructionData.AdditionalFixedMessage, &backupMetadata)
	if err != nil {
		return nil, 0, nil, err
	}

	backupID, err := backupRequestToID(&restoreRequest)
	if err != nil {
		return nil, 0, nil, err
	}
	if !backupMetadata.WalletBackupID.Equal(&backupID) { //nolint:staticcheck // to avoid confusion we do not call backupMetadata.Equal
		return nil, 0, nil, errors.New("wallet backup id in the metadata does not match the given id")
	}

	adminAddresses, err := utils.PubKeysToAddresses(backupMetadata.AdminsPublicKeys)
	if err != nil {
		return nil, 0, nil, err
	}

	err = processorutils.CheckMatchingCosigners(instructionData.Cosigners, adminAddresses, instructionData.CosignersThreshold, backupMetadata.AdminsThreshold)
	if err != nil {
		return nil, 0, nil, err
	}

	if !restoreRequest.Nonce.IsUint64() {
		return nil, 0, nil, errors.New("nonce too large")
	}

	keyActionNonce := restoreRequest.Nonce.Uint64()

	policyAtBackup, err := p.pStorage.SigningPolicy(backupID.RewardEpochID)
	if err != nil {
		return nil, 0, nil, err
	}

	isProviderAndAdmin, err := checkSigners(signers, policyAtBackup.Voters.Voters(), backupMetadata.AdminsPublicKeys, backupMetadata.AdminsThreshold) // threshold is checked at recover
	if err != nil {
		return nil, 0, nil, err
	}

	return &backupMetadata, keyActionNonce, isProviderAndAdmin, nil
}

// backupRequestToID constructs wallet backup ID from the restore request.
func backupRequestToID(req *wallet.ITeeWalletBackupManagerKeyDataProviderRestore) (wallets.WalletBackupID, error) {
	if len(req.BackupId.PublicKey) != 64 {
		return wallets.WalletBackupID{}, errors.New("unsupported public key format")
	}

	backupID := wallets.WalletBackupID{
		TeeID:         req.BackupId.TeeId,
		WalletID:      req.BackupId.WalletId,
		KeyID:         req.BackupId.KeyId,
		KeyType:       req.BackupId.KeyType,
		SigningAlgo:   req.BackupId.SigningAlgo,
		PublicKey:     append(make([]byte, 0, len(req.BackupId.PublicKey)), req.BackupId.PublicKey...),
		RewardEpochID: req.BackupId.RewardEpochId,
		RandomNonce:   req.BackupId.RandomNonce,
	}

	return backupID, nil
}

// checkSigners checks the following:
//
//   - all signers are either data providers or admins,
//   - the admin threshold is met,
//
// and returns a slice of booleans indicating whether each signer is both a provider and an admin.
func checkSigners(signers []common.Address, expectedProviders []common.Address, expectedAdmins []types.PublicKey, adminThreshold uint64) ([]bool, error) {
	adminAddresses := make(map[common.Address]bool)
	countAdmins := uint64(0)
	for _, admin := range expectedAdmins {
		adminPubKey, err := types.ParsePubKey(admin)
		if err != nil {
			return nil, err
		}
		adminAddress := crypto.PubkeyToAddress(*adminPubKey)
		adminAddresses[adminAddress] = true
		if slices.Contains(signers, adminAddress) {
			countAdmins++
		}
	}

	if countAdmins < adminThreshold {
		return nil, errors.New("admin threshold not reached")
	}

	isProviderAndAdmin := make([]bool, len(signers))
	for i, signer := range signers {
		isProvider := slices.Contains(expectedProviders, signer)
		_, isAdmin := adminAddresses[signer]
		if isProvider && isAdmin {
			isProviderAndAdmin[i] = true
		}
		if !isProvider && !isAdmin {
			return nil, errors.New("signed by an entity that is nether a provider nor an admin")
		}
	}

	return isProviderAndAdmin, nil
}

func (p *Processor) processKeySplitMessages(variableMessages []hexutil.Bytes, isProviderAndAdmin []bool, walletBackupId wallets.WalletBackupID) ([]*pkgbackup.KeySplit, []byte, error) {
	allKeySplits := make([]*pkgbackup.KeySplit, 0)
	duplicateCheck := make(map[common.Hash]int)

	restoreStatus := wallets.NewKeyDataProviderRestoreResultStatus()

outer:
	for i, keySplitMessage := range variableMessages {
		keySplitsPlaintext, err := p.Decrypt(keySplitMessage)
		if err != nil {
			restoreStatus.AddError(i, err)
			continue outer
		}

		keySplits, err := processKeySplitPlaintext(keySplitsPlaintext, walletBackupId, isProviderAndAdmin[i])
		if err != nil {
			restoreStatus.AddError(i, err)
			continue outer
		}

		for _, keySplit := range keySplits {
			keySplitHash, err := keySplit.HashForSigning()
			if err != nil {
				restoreStatus.AddError(i, err)
				continue outer
			}
			if _, ok := duplicateCheck[keySplitHash]; ok {
				err = errors.New("duplicate key split")
				restoreStatus.AddError(i, err)
				continue outer
			}
			duplicateCheck[keySplitHash] = i
		}

		allKeySplits = append(allKeySplits, keySplits...)
	}

	if !restoreStatus.Empty() {
		logger.Warnf("errors in restore process: %v", restoreStatus)
	}

	resultStatus, err := json.Marshal(restoreStatus)
	if err != nil {
		return nil, nil, err
	}

	return allKeySplits, resultStatus, nil
}

// processKeySplitPlaintext decodes plaintext to slice of KeySplits and validates them.
//
// If the plaintext belongs to an entity that is both data provider and admin, two splits are expected.
// Otherwise, one split is expected.
//
// It is checked that the splits have the expected backupID and that the signature is valid.
func processKeySplitPlaintext(plaintext []byte, walletBackupID wallets.WalletBackupID, isProviderAndAdmin bool) ([]*pkgbackup.KeySplit, error) {
	var err error
	keySplits := make([]*pkgbackup.KeySplit, 0)
	if !isProviderAndAdmin {
		var keySplit pkgbackup.KeySplit
		err = json.Unmarshal(plaintext, &keySplit)
		if err != nil {
			return nil, err
		}
		keySplits = append(keySplits, &keySplit)
	} else {
		var twoKeySplits [2]pkgbackup.KeySplit
		err = json.Unmarshal(plaintext, &twoKeySplits)
		if err != nil {
			return nil, err
		}
		keySplits = append(keySplits, &twoKeySplits[0], &twoKeySplits[1])
	}

	for _, keySplit := range keySplits {
		if !keySplit.WalletBackupID.Equal(&walletBackupID) {
			return nil, errors.New("wallet backup id in the share does not match the id in the key split")
		}

		err = keySplit.VerifySignature()
		if err != nil {
			return nil, err
		}
	}

	return keySplits, nil
}
