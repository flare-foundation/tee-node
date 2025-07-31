package walletutils

import (
	"encoding/json"
	"slices"

	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/policy"
	"github.com/flare-foundation/tee-node/internal/wallets"
	"github.com/flare-foundation/tee-node/internal/wallets/backup"
	pkgbackup "github.com/flare-foundation/tee-node/pkg/backup"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/tee"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/pkg/errors"
)

func NewWallet(instructionData *instruction.DataFixed) ([]byte, error) {
	newWalletRequest, err := types.ParseNewWalletRequest(instructionData)
	if err != nil {
		return nil, err
	}

	err = types.CheckNewWalletRequest(newWalletRequest)
	if err != nil {
		return nil, err
	}
	if newWalletRequest.TeeId != node.TeeID() {
		return nil, errors.New("tee id does not match")
	}

	newWallet, err := wallets.CreateNewWallet(newWalletRequest)
	if err != nil {
		return nil, err
	}

	wallets.Storage.Lock()
	defer wallets.Storage.Unlock()
	err = wallets.Storage.StoreWallet(newWallet)
	if err != nil {
		return nil, err
	}
	// get stored wallet to also have the correct walletStatus
	storedWallet, err := wallets.Storage.GetWallet(types.WalletKeyIdPair{WalletId: newWallet.WalletId, KeyId: newWallet.KeyId})
	if err != nil {
		return nil, err
	}

	existenceProof := wallets.WalletToKeyExistenceProof(storedWallet, node.TeeID())
	existenceProofEncoded, err := structs.Encode(wallet.KeyExistenceStructArg, existenceProof)
	if err != nil {
		return nil, err
	}

	return existenceProofEncoded, nil
}

func ValidateNewWallet(instructionData *instruction.DataFixed) error {
	newWalletRequest, err := types.ParseNewWalletRequest(instructionData)
	if err != nil {
		return err
	}

	err = types.CheckNewWalletRequest(newWalletRequest)
	if err != nil {
		return err
	}
	if newWalletRequest.TeeId != node.TeeID() {
		return errors.New("tee id does not match")
	}

	_, err = utils.ParsePubKeys(newWalletRequest.ConfigConstants.AdminsPublicKeys)
	if err != nil {
		return err
	}

	wallets.Storage.RLock()
	walletNonce, err := wallets.Storage.GetNonce(types.WalletKeyIdPair{WalletId: newWalletRequest.WalletId, KeyId: newWalletRequest.KeyId})
	wallets.Storage.RUnlock()
	if err != nil {
		return err
	}
	if walletNonce != 0 {
		return errors.New("wallet nonce already changed")
	}

	return nil
}

func DeleteWallet(instructionData *instruction.DataFixed) error {
	delWalletRequest, err := types.ParseDeleteWalletRequest(instructionData)
	if err != nil {
		return err
	}

	walletKeyId := types.WalletKeyIdPair{WalletId: delWalletRequest.WalletId, KeyId: delWalletRequest.KeyId}

	wallets.Storage.Lock()
	defer wallets.Storage.Unlock()
	err = wallets.Storage.CheckNonce(walletKeyId, delWalletRequest.Nonce.Uint64())
	if err != nil {
		return err
	}

	wallets.Storage.RemoveWallet(walletKeyId)
	wallets.Storage.UpdateNonce(walletKeyId, delWalletRequest.Nonce.Uint64())

	return nil
}

func ValidateDeleteWallet(instructionData *instruction.DataFixed) error {
	delWalletRequest, err := types.ParseDeleteWalletRequest(instructionData)
	if err != nil {
		return err
	}
	walletKeyId := types.WalletKeyIdPair{WalletId: delWalletRequest.WalletId, KeyId: delWalletRequest.KeyId}

	exists := wallets.Storage.WalletExists(walletKeyId)
	if exists {
		return errors.New("wallet not deleted, still exists")
	}

	wallets.Storage.RLock()
	walletNonce, err := wallets.Storage.GetNonce(walletKeyId)
	wallets.Storage.RUnlock()
	if err != nil {
		return err
	}
	if walletNonce != delWalletRequest.Nonce.Uint64() {
		return errors.New("wallet nonce already changed")
	}

	return nil
}

func KeyDataProviderRestore(instructionData *instruction.DataFixed,
	variableMessages []hexutil.Bytes,
	signers []common.Address,
) ([]byte, []byte, error) {
	walletBackupMetadata, newWalletNonce, signersBothRoles, err := keyDataProviderRestoreCheck(instructionData, signers)
	if err != nil {
		return nil, nil, err
	}
	walletBackupId := walletBackupMetadata.WalletBackupId
	walletKeyId := types.WalletKeyIdPair{WalletId: walletBackupId.WalletId, KeyId: walletBackupId.KeyId}

	wallets.Storage.RLock()
	err = wallets.Storage.CheckNonce(walletKeyId, newWalletNonce)
	wallets.Storage.RUnlock()
	if err != nil {
		return nil, nil, err
	}

	keySplits, resultStatus, err := processKeySplitMessages(variableMessages, signersBothRoles, walletBackupId)
	if err != nil {
		return nil, nil, err
	}

	newWallet, err := backup.RecoverWallet(keySplits, walletBackupMetadata)
	if err != nil {
		return nil, resultStatus, err
	}

	wallets.Storage.Lock()
	defer wallets.Storage.Unlock()
	if wallets.Storage.WalletExists(walletKeyId) {
		return nil, nil, errors.New("wallet with given walletId and keyId already exists")
	}

	wallets.Storage.UpdateNonce(walletKeyId, newWalletNonce)
	err = wallets.Storage.StoreWallet(newWallet)
	if err != nil {
		return nil, nil, err
	}

	// get stored wallet to also have the correct walletStatus
	storedWallet, err := wallets.Storage.GetWallet(walletKeyId)
	if err != nil {
		return nil, nil, err
	}
	existenceProof := wallets.WalletToKeyExistenceProof(storedWallet, node.TeeID())
	existenceProofEncoded, err := structs.Encode(wallet.KeyExistenceStructArg, existenceProof)
	if err != nil {
		return nil, nil, err
	}

	return existenceProofEncoded, resultStatus, nil
}

func ValidateKeyDataProviderRestore(instructionData *instruction.DataFixed,
	variableMessages []hexutil.Bytes,
	signers []common.Address,
) ([]byte, error) {
	walletBackupMetadata, restoredWalletNonce, signersBothRoles, err := keyDataProviderRestoreCheck(instructionData, signers)
	if err != nil {
		return nil, err
	}
	walletBackupId := walletBackupMetadata.WalletBackupId
	walletKeyId := types.WalletKeyIdPair{WalletId: walletBackupId.WalletId, KeyId: walletBackupId.KeyId}

	keySplits, resultStatus, err := processKeySplitMessages(variableMessages, signersBothRoles, walletBackupId)
	if err != nil {
		return nil, err
	}

	_, err = backup.RecoverWallet(keySplits, walletBackupMetadata)
	if err != nil {
		return resultStatus, err
	}

	wallets.Storage.RLock()
	exists := wallets.Storage.WalletExists(walletKeyId)
	checkNonce, err := wallets.Storage.GetNonce(walletKeyId)
	wallets.Storage.RUnlock()
	if !exists {
		return nil, errors.New("wallet does not exists")
	}
	if err != nil {
		return nil, err
	}
	if checkNonce != restoredWalletNonce {
		return nil, errors.New("wallet nonce already changed")
	}

	return resultStatus, nil
}

func keyDataProviderRestoreCheck(instructionData *instruction.DataFixed, signers []common.Address) (*pkgbackup.WalletBackupMetaData, uint64, []bool, error) {
	restoreWalletRequest, err := types.ParseKeyDataProviderRestoreRequest(instructionData)
	if err != nil {
		return nil, 0, nil, err
	}

	var walletBackupMetadata pkgbackup.WalletBackupMetaData
	err = json.Unmarshal(instructionData.AdditionalFixedMessage, &walletBackupMetadata)
	if err != nil {
		return nil, 0, nil, err
	}

	walletBackupId, err := backupRequestToBackupId(&restoreWalletRequest)
	if err != nil {
		return nil, 0, nil, err
	}
	if walletBackupMetadata.WalletBackupId != walletBackupId {
		return nil, 0, nil, errors.New("wallet backup id in the metadata does not match the given id")
	}
	restoredWalletNonce := restoreWalletRequest.Nonce.Uint64()

	policyAtBackup, err := policy.Storage.SigningPolicy(walletBackupId.RewardEpochID)
	if err != nil {
		return nil, 0, nil, err
	}
	isProviderAndAdmin, err := checkSigners(signers, policyAtBackup.Voters.Voters(), walletBackupMetadata.AdminsPublicKeys, walletBackupMetadata.AdminsThreshold) // threshold is checked at recover
	if err != nil {
		return nil, 0, nil, err
	}
	return &walletBackupMetadata, restoredWalletNonce, isProviderAndAdmin, nil
}

func processKeySplitMessages(variableMessages []hexutil.Bytes, isProviderAndAdmin []bool, walletBackupId types.WalletBackupId) ([]*pkgbackup.KeySplit, []byte, error) {
	allKeySplits := make([]*pkgbackup.KeySplit, 0)
	duplicateCheck := make(map[common.Hash]int)

	errorPositions := make([]int, 0)
	errorLogs := make([]string, 0)
	for i, keySplitMessage := range variableMessages {
		keySplits, err := processKeySplitMessage(keySplitMessage, walletBackupId, isProviderAndAdmin[i])
		if err != nil {
			errorPositions = append(errorPositions, i)
			errorLogs = append(errorLogs, err.Error())
			continue
		}

		for _, keySplit := range keySplits {
			keySplitHash, err := keySplit.HashForSigning()
			if err != nil {
				errorPositions = append(errorPositions, i)
				errorLogs = append(errorLogs, err.Error())
				continue
			}
			if j, ok := duplicateCheck[keySplitHash]; ok {
				errorPositions = append(errorPositions, i, j)
				err = errors.New("duplicate key split")
				errorLogs = append(errorLogs, err.Error(), err.Error())
				continue
			}
			duplicateCheck[keySplitHash] = i
		}

		allKeySplits = append(allKeySplits, keySplits...)
	}

	resultStatus, err := json.Marshal(types.KeyDataProviderRestoreResultStatus{ErrorPositions: errorPositions, ErrorLogs: errorLogs})
	if err != nil {
		return nil, nil, err
	}

	return allKeySplits, resultStatus, nil
}

func processKeySplitMessage(keySplitMessage []byte, walletBackupId types.WalletBackupId, isProviderAndAdmin bool) ([]*pkgbackup.KeySplit, error) {
	keySplitsPlaintext, err := node.Decrypt(keySplitMessage)
	if err != nil {
		return nil, err
	}

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
		if keySplit.WalletBackupId != walletBackupId {
			return nil, errors.New("wallet backup id in the share does not match the id in the key split")
		}

		err = keySplit.VerifySignature()
		if err != nil {
			return nil, err
		}
	}

	return keySplits, nil
}

func checkSigners(signers []common.Address, expectedProviders []common.Address, expectedAdmins []tee.PublicKey, adminThreshold uint64) ([]bool, error) {
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

func backupRequestToBackupId(req *wallet.ITeeWalletBackupManagerKeyDataProviderRestore) (types.WalletBackupId, error) {
	if req.BackupId.RewardEpochId == nil {
		return types.WalletBackupId{}, errors.New("reward epoch not given")
	}

	walletBackupId := types.WalletBackupId{
		TeeId:         req.BackupId.TeeId,
		WalletId:      req.BackupId.WalletId,
		KeyId:         req.BackupId.KeyId,
		OpType:        req.BackupId.OpType,
		RewardEpochID: uint32(req.BackupId.RewardEpochId.Uint64()),
		RandomNonce:   [32]byte{},
	}
	if len(req.BackupId.PublicKey) != 64 {
		return types.WalletBackupId{}, errors.New("unsupported public key format")
	}
	copy(walletBackupId.PublicKey.X[:], req.BackupId.PublicKey[:32])
	copy(walletBackupId.PublicKey.Y[:], req.BackupId.PublicKey[32:])

	randomNonce := req.BackupId.RandomNonce.Bytes()
	if len(randomNonce) > 32 {
		return types.WalletBackupId{}, errors.New("random nonce too big")
	}
	randomNonce = append(make([]byte, 32-len(randomNonce)), randomNonce...)
	copy(walletBackupId.RandomNonce[:], randomNonce)

	return walletBackupId, nil
}
