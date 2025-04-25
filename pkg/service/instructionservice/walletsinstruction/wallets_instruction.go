package walletsinstruction

import (
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/pkg/errors"

	api "tee-node/api/types"
	"tee-node/pkg/config"
	"tee-node/pkg/node"
	"tee-node/pkg/policy"
	walletsservice "tee-node/pkg/service/walletservice"
	"tee-node/pkg/wallets"
)

// NewWallet creates a new wallet using the provided instruction data.
// Parameters:
// - instructionData: Contains the data needed to create a new wallet.
func NewWallet(instructionData *instruction.DataFixed) error {
	newWalletRequest, err := api.ParseNewWalletRequest(instructionData)
	if err != nil {
		return err
	}

	err = api.CheckNewWalletRequest(newWalletRequest)
	if err != nil {
		return err
	}

	wallet, err := wallets.CreateNewWallet(newWalletRequest)
	if err != nil {
		return err
	}

	activePolicy := policy.GetActiveSigningPolicy()
	pubKeysMap := policy.GetActiveSigningPolicyPublicKeysMap()
	activePolicyPublicKeys, err := policy.GetSigningPolicyPublicKeys(activePolicy, pubKeysMap)
	if err != nil {
		return err
	}
	normalizedWeights := config.WeightsNormalization(activePolicy.Weights)

	walletBackup, err := wallets.BackupWallet(wallet, activePolicyPublicKeys, config.DataProvidersBackupThreshold, normalizedWeights, activePolicy.RewardEpochId)
	if err != nil {
		return err
	}

	err = wallets.StoreWallet(wallet)
	if err != nil {
		return err
	}
	wallets.StoreBackup(walletBackup)

	return nil
}

// DeleteWallet removes an existing wallet using the provided instruction data.
// Parameters:
// - instructionData: Contains the data needed to delete a wallet.
//   - delWalletRequest: Decoded from instructionData, includes:
//   - WalletId: The ID of the wallet to be deleted.
//   - KeyId: The key ID associated with the wallet.
func DeleteWallet(instructionData *instruction.DataFixed) error {
	delWalletRequest, err := api.ParseDeleteWalletRequest(instructionData)
	if err != nil {
		return err
	}

	walletKeyId := wallets.WalletKeyIdPair{WalletId: delWalletRequest.WalletId, KeyId: delWalletRequest.KeyId}
	wallet, err := wallets.GetWallet(walletKeyId)
	if err != nil {
		return err
	}

	myNodeId := node.GetTeeId()
	activeRewardEpoch := policy.GetActiveSigningPolicy().RewardEpochId
	walletBackupId := wallets.WalletBackupId{
		TeeId:         myNodeId,
		WalletId:      wallet.WalletId,
		KeyId:         wallet.KeyId,
		PublicKey:     api.PubKeyToBytes(&wallet.PrivateKey.PublicKey),
		OpType:        wallet.OpType,
		RewardEpochID: activeRewardEpoch,
	}

	wallets.RemoveWallet(walletKeyId)
	wallets.RemoveBackup(walletBackupId)

	return nil
}

func KeyMachineBackupRemove(instructionData *instruction.DataFixed) ([]byte, error) {
	return nil, errors.New("WALLET KEY_MACHINE_BACKUP_REMOVE command not implemented yet")
}

func KeyDataProviderRestoreInit(instructionData *instruction.DataFixed) ([]byte, error) {
	restoreWalletRequest, err := api.ParseKeyDataProviderRestoreRequest(instructionData)
	if err != nil {
		return nil, err
	}

	walletBackupId, err := walletsservice.BackupRequestToBackupId(&restoreWalletRequest)
	if err != nil {
		return nil, err
	}

	err = wallets.InitPendingBackup(walletBackupId)
	if err != nil {
		return nil, err
	}
	wallets.PendingWalletGarbageCollector.TrackRequest(walletBackupId)

	return nil, nil
}
