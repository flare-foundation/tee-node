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
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
)

func (p *Processor) keyDataProviderRestoreCheck(
	instructionData *instruction.DataFixed,
	signers []common.Address,
	teeID common.Address,
) (*pkgbackup.WalletBackupMetaData, uint64, []bool, error) {
	restoreRequest, err := wallets.ParseKeyDataProviderRestore(instructionData)
	if err != nil {
		return nil, 0, nil, err
	}

	teePubKey, err := types.ParsePubKey(types.PublicKey{X: restoreRequest.TeePublicKey.X, Y: restoreRequest.TeePublicKey.Y})
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
	if backupMetadata.WalletBackupID != backupID {
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
	restoredWalletNonce := restoreRequest.Nonce.Uint64()

	policyAtBackup, err := p.pStorage.SigningPolicy(backupID.RewardEpochID)
	if err != nil {
		return nil, 0, nil, err
	}
	isProviderAndAdmin, err := checkSigners(signers, policyAtBackup.Voters.Voters(), backupMetadata.AdminsPublicKeys, backupMetadata.AdminsThreshold) // threshold is checked at recover
	if err != nil {
		return nil, 0, nil, err
	}
	return &backupMetadata, restoredWalletNonce, isProviderAndAdmin, nil
}

func (p *Processor) processKeySplitMessages(variableMessages []hexutil.Bytes, isProviderAndAdmin []bool, walletBackupId wallets.WalletBackupID) ([]*pkgbackup.KeySplit, []byte, error) {
	allKeySplits := make([]*pkgbackup.KeySplit, 0)
	duplicateCheck := make(map[common.Hash]int)

	errorPositions := make([]int, 0)
	errorLogs := make([]string, 0)
	var keySplits []*pkgbackup.KeySplit
	for i, keySplitMessage := range variableMessages {
		keySplitsPlaintext, err := p.Decrypt(keySplitMessage)
		if err != nil {
			goto errorSave
		}
		keySplits, err = processKeySplitMessage(keySplitsPlaintext, walletBackupId, isProviderAndAdmin[i])
		if err != nil {
			goto errorSave
		}

		for _, keySplit := range keySplits {
			var keySplitHash common.Hash
			keySplitHash, err = keySplit.HashForSigning()
			if err != nil {
				goto errorSave
			}
			if _, ok := duplicateCheck[keySplitHash]; ok {
				err = errors.New("duplicate key split")
				goto errorSave
			}
			duplicateCheck[keySplitHash] = i
		}

		allKeySplits = append(allKeySplits, keySplits...)

	errorSave:
		if err != nil {
			errorPositions = append(errorPositions, i)
			errorLogs = append(errorLogs, err.Error())
		}
	}

	resultStatus, err := json.Marshal(wallets.KeyDataProviderRestoreResultStatus{ErrorPositions: errorPositions, ErrorLogs: errorLogs})
	if err != nil {
		return nil, nil, err
	}

	return allKeySplits, resultStatus, nil
}

func processKeySplitMessage(keySplitsPlaintext []byte, walletBackupId wallets.WalletBackupID, isProviderAndAdmin bool) ([]*pkgbackup.KeySplit, error) {
	var err error
	keySplits := make([]*pkgbackup.KeySplit, 0)
	if !isProviderAndAdmin {
		var keySplit pkgbackup.KeySplit
		err = json.Unmarshal(keySplitsPlaintext, &keySplit)
		if err != nil {
			return nil, err
		}
		keySplits = append(keySplits, &keySplit)
	} else {
		var twoKeySplits [2]pkgbackup.KeySplit
		err = json.Unmarshal(keySplitsPlaintext, &twoKeySplits)
		if err != nil {
			return nil, err
		}
		keySplits = append(keySplits, &twoKeySplits[0])
		keySplits = append(keySplits, &twoKeySplits[1])
	}

	for _, keySplit := range keySplits {
		if keySplit.WalletBackupID != walletBackupId {
			return nil, errors.New("wallet backup id in the share does not match the id in the key split")
		}

		err = keySplit.VerifySignature()
		if err != nil {
			return nil, err
		}
	}

	return keySplits, nil
}

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

func backupRequestToID(req *wallet.ITeeWalletBackupManagerKeyDataProviderRestore) (wallets.WalletBackupID, error) {
	if req.BackupId.RewardEpochId == nil {
		return wallets.WalletBackupID{}, errors.New("reward epoch not given")
	}

	backupID := wallets.WalletBackupID{
		TeeID:         req.BackupId.TeeId,
		WalletID:      req.BackupId.WalletId,
		KeyID:         req.BackupId.KeyId,
		KeyType:       req.BackupId.KeyType,
		SigningAlgo:   req.BackupId.SigningAlgo,
		RewardEpochID: uint32(req.BackupId.RewardEpochId.Uint64()),
		RandomNonce:   common.Hash{},
	}
	if len(req.BackupId.PublicKey) != 64 {
		return wallets.WalletBackupID{}, errors.New("unsupported public key format")
	}
	copy(backupID.PublicKey.X[:], req.BackupId.PublicKey[:32])
	copy(backupID.PublicKey.Y[:], req.BackupId.PublicKey[32:])

	randomNonce := req.BackupId.RandomNonce.Bytes()
	if len(randomNonce) > 32 {
		return wallets.WalletBackupID{}, errors.New("random nonce too big")
	}
	randomNonce = append(make([]byte, 32-len(randomNonce), 32), randomNonce...)
	copy(backupID.RandomNonce[:], randomNonce)

	return backupID, nil
}
