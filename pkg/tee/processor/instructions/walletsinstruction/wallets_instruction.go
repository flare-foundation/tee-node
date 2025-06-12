package walletsinstruction

import (
	"encoding/json"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/pkg/errors"

	"tee-node/api/types"
	"tee-node/pkg/tee/node"
	"tee-node/pkg/tee/policy"
	"tee-node/pkg/tee/wallets"
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
	if newWalletRequest.TeeId != node.GetTeeId() {
		return nil, errors.New("tee id does not match")
	}

	newWallet, err := wallets.CreateNewWallet(newWalletRequest)
	if err != nil {
		return nil, err
	}

	err = wallets.StoreWallet(newWallet)
	if err != nil {
		return nil, err
	}

	result := wallets.WalletToKeyExistenceProof(newWallet, node.GetTeeId())

	// abi.Arguments{wallet.MessageArguments[wallet.KeyGenerate]}.Pack(originalMessage)
	// todo: change to abi encoded
	resultEncoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}

	return resultEncoded, nil
}

func DeleteWallet(instructionData *instruction.DataFixed) error {
	delWalletRequest, err := types.ParseDeleteWalletRequest(instructionData)
	if err != nil {
		return err
	}

	walletKeyId := wallets.WalletKeyIdPair{WalletId: delWalletRequest.WalletId, KeyId: delWalletRequest.KeyId}

	wallets.RemoveWallet(walletKeyId)

	return nil
}

func KeyMachineBackupRemove(instructionData *instruction.DataFixed) ([]byte, error) {
	return nil, errors.New("WALLET KEY_MACHINE_BACKUP_REMOVE command not implemented yet")
}

func KeyDataProviderRestore(instructionData *instruction.DataFixed,
	variableMessages, adminVariableMessages [][]byte,
	providers, admins map[common.Address][]byte) ([]byte, error) {
	restoreWalletRequest, err := types.ParseKeyDataProviderRestoreRequest(instructionData)
	if err != nil {
		return nil, err
	}

	var walletBackupMetadata wallets.WalletBackupMetaData
	err = json.Unmarshal(instructionData.AdditionalFixedMessage, &walletBackupMetadata)
	if err != nil {
		return nil, err
	}

	walletBackupId, err := backupRequestToBackupId(&restoreWalletRequest)
	if err != nil {
		return nil, err
	}
	if walletBackupMetadata.WalletBackupId != walletBackupId {
		return nil, errors.New("wallet backup id in the metadata does not match the given id")
	}

	err = checkAdmins(admins, walletBackupMetadata.AdminsPublicKeys, walletBackupMetadata.AdminsThreshold)
	if err != nil {
		return nil, err
	}

	policyAtBackup, err := policy.GetSigningPolicy(walletBackupId.RewardEpochID)
	if err != nil {
		return nil, err
	}
	err = checkProviders(providers, policyAtBackup.Voters) // threshold is checked at recover
	if err != nil {
		return nil, err
	}
	keySplits, err := processKeySplitMessages(variableMessages, adminVariableMessages, walletBackupId)
	if err != nil {
		return nil, err
	}

	newWallet, err := wallets.RecoverWallet(keySplits, walletBackupMetadata)
	if err != nil {
		return nil, err
	}

	err = wallets.StoreWallet(newWallet)
	if err != nil {
		return nil, err
	}

	result := wallets.WalletToKeyExistenceProof(newWallet, node.GetTeeId())
	// todo: change to abi encoded
	resultEncoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}

	return resultEncoded, nil
}

func processKeySplitMessages(variableMessages, adminVariableMessages [][]byte, walletBackupId wallets.WalletBackupId) ([]*wallets.KeySplit, error) {
	keySplits := make([]*wallets.KeySplit, 0)
	duplicateCheck := make(map[common.Hash]bool)
	for i, keySplitMessage := range append(variableMessages, adminVariableMessages...) {
		keySplit, keySplitHash, err := processKeySplitMessage(keySplitMessage, walletBackupId, i >= len(variableMessages))
		if err != nil {
			return nil, err
		}

		if _, ok := duplicateCheck[keySplitHash]; ok {
			return nil, errors.New("duplicate key split")
		}
		duplicateCheck[keySplitHash] = true
		keySplits = append(keySplits, keySplit)
	}

	return keySplits, nil
}

func processKeySplitMessage(keySplitMessage []byte, walletBackupId wallets.WalletBackupId, isAdmin bool) (*wallets.KeySplit, common.Hash, error) {
	keySplitPlaintext, err := node.Decrypt(keySplitMessage)
	if err != nil {
		return nil, common.Hash{}, err
	}

	var keySplit wallets.KeySplit
	err = json.Unmarshal(keySplitPlaintext, &keySplit)
	if err != nil {
		return nil, common.Hash{}, err
	}

	if keySplit.WalletBackupId != walletBackupId {
		return nil, common.Hash{}, errors.New("wallet backup id in the share does not match the id in the key split")
	}
	if keySplit.IsAdmin != isAdmin {
		return nil, common.Hash{}, errors.New("error in the the key split admin vs provider role")
	}

	err = keySplit.VerifySignature()
	if err != nil {
		return nil, common.Hash{}, err
	}

	keySplitHash, err := keySplit.HashForSigning()
	if err != nil {
		return nil, common.Hash{}, err
	}

	return &keySplit, keySplitHash, nil
}
func checkAdmins(givenAdmins map[common.Address][]byte, expectedAdmins []types.ECDSAPublicKey, threshold uint64) error {
	adminsAddresses := make(map[common.Address]bool)
	for _, admin := range expectedAdmins {
		adminPubKey, err := types.ParsePubKey(admin)
		if err != nil {
			return err
		}
		adminsAddresses[crypto.PubkeyToAddress(*adminPubKey)] = true
	}

	for givenAdmin := range givenAdmins {
		if _, ok := adminsAddresses[givenAdmin]; !ok {
			return errors.New("signed by a non-admin")
		}
	}
	if uint64(len(givenAdmins)) < threshold {
		return errors.New("admin threshold not reached")
	}
	return nil
}

func checkProviders(givenProviders map[common.Address][]byte, expectedProviders []common.Address) error {
	for givenProvider := range givenProviders {
		if ok := slices.Contains(expectedProviders, givenProvider); !ok {
			return errors.New("signed by a non-provider")
		}
	}

	return nil
}

func backupRequestToBackupId(req *wallet.ITeeWalletBackupManagerKeyDataProviderRestore) (wallets.WalletBackupId, error) {
	if req.BackupId.RewardEpochId == nil {
		return wallets.WalletBackupId{}, errors.New("reward epoch not given")
	}

	walletBackupId := wallets.WalletBackupId{
		TeeId:         req.BackupId.TeeId,
		WalletId:      req.BackupId.WalletId,
		KeyId:         req.BackupId.KeyId,
		OpType:        req.BackupId.OpType,
		RewardEpochID: uint32(req.BackupId.RewardEpochId.Uint64()),
	}
	if len(req.BackupId.PublicKey) != 64 {
		return wallets.WalletBackupId{}, errors.New("unsupported public key format")
	}
	copy(walletBackupId.PublicKey.X[:], req.BackupId.PublicKey[:32])
	copy(walletBackupId.PublicKey.Y[:], req.BackupId.PublicKey[32:])

	return walletBackupId, nil
}
