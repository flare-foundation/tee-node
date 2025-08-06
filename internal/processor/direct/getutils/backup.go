package getutils

import (
	"encoding/json"

	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/policy"
	"github.com/flare-foundation/tee-node/internal/wallets"
	"github.com/flare-foundation/tee-node/internal/wallets/backup"
	"github.com/flare-foundation/tee-node/pkg/types"
)

// todo: the returned backup should be uniquely identifiable
func GetBackupPackage(getAction *types.DirectInstruction) ([]byte, error) {
	var walletKeyId types.WalletKeyIDPair
	err := json.Unmarshal(getAction.Message, &walletKeyId)
	if err != nil {
		return nil, err
	}
	myTeeId := node.TeeID()

	wallets.Storage.RLock()
	wallet, err := wallets.Storage.GetWallet(walletKeyId)
	wallets.Storage.RUnlock()
	if err != nil {
		return nil, err
	}

	policy.Storage.RLock()
	activePolicy, err := policy.Storage.ActiveSigningPolicy()
	if err != nil {
		policy.Storage.RUnlock()
		return nil, err
	}
	activePolicyPublicKeys, err := policy.Storage.GetActiveSigningPolicyPublicKeysSlice()
	policy.Storage.RUnlock()
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
		types.WalletGetBackupResponse{WalletBackup: walletBackupBytes, BackupID: walletBackup.WalletBackupID},
	)
	if err != nil {
		return nil, err
	}

	return responseBytes, nil
}
