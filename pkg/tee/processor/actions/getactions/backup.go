package getactions

import (
	"encoding/json"
	"tee-node/api/types"
	"tee-node/pkg/tee/node"
	"tee-node/pkg/tee/policy"
	"tee-node/pkg/tee/wallets"
)

// todo: the returned backup should be uniquely identifiable
func GetBackupPackage(getAction *types.ActionData) ([]byte, error) {
	var walletKeyId wallets.WalletKeyIdPair
	err := json.Unmarshal(getAction.Message, &walletKeyId)
	if err != nil {
		return nil, err
	}
	wallet, err := wallets.GetWallet(walletKeyId)
	if err != nil {
		return nil, err
	}

	myTeeId := node.GetTeeId()

	activePolicy, err := policy.GetActiveSigningPolicy()
	if err != nil {
		return nil, err
	}
	pubKeysMap := policy.GetActiveSigningPolicyPublicKeysMap()
	activePolicyPublicKeys, err := policy.ToSigningPolicyPublicKeysSlice(activePolicy, pubKeysMap)
	if err != nil {
		return nil, err
	}

	walletBackup, err := wallets.BackupWallet(
		wallet, activePolicyPublicKeys,
		activePolicy.Weights,
		activePolicy.RewardEpochId,
		myTeeId,
	)
	if err != nil {
		return nil, err
	}

	walletBackupBytes, err := json.Marshal(walletBackup)
	if err != nil {
		return nil, err
	}

	responseBytes, err := json.Marshal(
		types.WalletGetBackupResponse{WalletBackup: walletBackupBytes, BackupId: types.WalletBackupId(walletBackup.WalletBackupId)},
	)
	if err != nil {
		return nil, err
	}

	return responseBytes, nil
}
