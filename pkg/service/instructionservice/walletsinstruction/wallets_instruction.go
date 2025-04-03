package walletsinstruction

import (
	"encoding/hex"
	"encoding/json"

	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/google/logger"
	"github.com/pkg/errors"

	api "tee-node/api/types"
	"tee-node/pkg/node"
	"tee-node/pkg/wallets"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gorilla/websocket"
)

// NewWallet creates a new wallet using the provided instruction data.
// Parameters:
// - instructionData: Contains the data needed to create a new wallet.
//   - newWalletRequest: Decoded from instructionData, includes:
//   - WalletId: The ID of the wallet to be created.
//   - KeyId: The key ID associated with the wallet.
func NewWallet(instructionData *instruction.DataFixed) error {
	newWalletRequest, err := api.ParseNewWalletRequest(instructionData)
	if err != nil {
		return err
	}

	err = wallets.CreateNewWallet(wallets.WalletKeyIdPair{WalletId: newWalletRequest.WalletId, KeyId: newWalletRequest.KeyId})
	if err != nil {
		return err
	}

	return nil
}

// DeleteWallet removes an existing wallet using the provided instruction data.
// Parameters:
// - instructionData: Contains the data needed to delete a wallet.
//   - delWalletRequest: Decoded from instructionData, includes:
//   - WalletId: The ID of the wallet to be deleted.
//   - KeyId: The key ID associated with the wallet.
func DeleteWallet(instructionData *instruction.DataFixed) error {
	delWalletRequest, err := api.NewDeleteWalletRequest(instructionData)
	if err != nil {
		return err
	}

	wallets.RemoveWallet(wallets.WalletKeyIdPair{WalletId: delWalletRequest.WalletId, KeyId: delWalletRequest.KeyId})

	return nil
}

// SplitWallet splits a wallet into shares for backup purposes.
// Parameters:
// - instructionData: Contains the data needed to split a wallet.
//   - splitWalletRequest: Decoded from instructionData, includes:
//   - BackupId: The ID for the backup process.
//   - WalletId: The ID of the wallet to be split.
//   - KeyId: The key ID associated with the wallet.
//   - BackupTeeMachines: List of machines to store the wallet shares on (teeIds and urls).
//   - ShamirThreshold: The threshold for Shamir's Secret Sharing.
//
// - signatures: Digital signatures for the operation.
func SplitWallet(instructionData *instruction.DataFixed, signatures [][]byte) error {
	splitWalletRequest, err := api.NewSplitWalletRequest(instructionData)
	if err != nil {
		return err
	}

	var additionalFixedMessage api.SplitWalletAdditionalFixedMessage
	err = json.Unmarshal(instructionData.AdditionalFixedMessage, &additionalFixedMessage)
	if err != nil {
		return err
	}

	numShares := len(splitWalletRequest.BackupTeeMachines)

	splits, err := wallets.SplitWalletById(
		wallets.BackupWalletKeyIdTriple{BackupId: splitWalletRequest.BackupId, WalletId: splitWalletRequest.WalletId, KeyId: splitWalletRequest.KeyId},
		numShares,
		int(splitWalletRequest.ShamirThreshold.Uint64()),
	)
	if err != nil {
		return err
	}

	wsConns := make([]*websocket.Conn, numShares)
	for i, host := range splitWalletRequest.BackupTeeMachines {
		// Create a new WebSocket connection
		wsConns[i], _, err = websocket.DefaultDialer.Dial(host.Url+"/share_wallet", nil) // todo timeout
		if err != nil {
			return err
		}
	}

	// todo attest others, itd.
	for i, conn := range wsConns {
		err = wallets.SendShare(conn, splits[i], splitWalletRequest.BackupTeeMachines[i].TeeId.String(), additionalFixedMessage.PublicKeys[i], instructionData, signatures)
		if err != nil {
			return err
		}
		conn.Close()
	}

	return nil
}

// RecoverWallet reconstructs a wallet from its shares.
// Parameters:
// - instructionData: Contains the data needed to recover a wallet.
//   - recoverWalletRequest: Decoded from instructionData, includes:
//   - BackupId: The ID for the backup process.
//   - WalletId: The ID of the wallet to be recovered.
//   - KeyId: The key ID associated with the wallet.
//   - BackupTeeMachines: List of machines holding the wallet shares (teeIds and urls).
//   - PublicKey: The public key of the TEE nodeId
//
// - signatures: Digital signatures for the operation.
func RecoverWallet(instructionData *instruction.DataFixed, signatures [][]byte) error {
	recoverWalletRequest, err := api.NewRecoverWalletRequest(instructionData)
	if err != nil {
		return err
	}

	var additionalFixedMessage api.RecoverWalletRequestAdditionalFixedMessage
	err = json.Unmarshal(instructionData.AdditionalFixedMessage, &additionalFixedMessage)
	if err != nil {
		return err
	}

	myNode := node.GetNodeId()
	if hex.EncodeToString(myNode.EncryptionKey.PublicKey[:]) != common.Bytes2Hex(recoverWalletRequest.PublicKey) {
		return errors.New("public key not matching node's public key")
	}

	numShares := len(recoverWalletRequest.BackupTeeMachines)

	wsConns := make([]*websocket.Conn, numShares)
	for i, backupMachine := range recoverWalletRequest.BackupTeeMachines {
		// Create a new WebSocket connection
		wsConns[i], _, err = websocket.DefaultDialer.Dial(backupMachine.Url+"/recover_wallet", nil) // todo timeout
		if err != nil {
			return err
		}
	}
	// todo send splits, attest others, itd.
	splits := make([]*wallets.WalletShare, 0)
	for i, conn := range wsConns {
		share, err := wallets.RequestShare(
			conn,
			additionalFixedMessage.TeeIds[i],
			i,
			instructionData,
			signatures,
		)
		if err != nil {
			return err
		}
		splits = append(splits, share)

		logger.Infof("obtained a share for wallet %s", recoverWalletRequest.WalletId)

		conn.Close()
	}

	address := common.HexToAddress(additionalFixedMessage.Address)
	reconstructedWallet, err := wallets.JointWallet(
		splits,
		wallets.BackupWalletKeyIdTriple{WalletId: recoverWalletRequest.WalletId, KeyId: recoverWalletRequest.KeyId, BackupId: recoverWalletRequest.BackupId},
		address, int(additionalFixedMessage.Threshold))
	if err != nil {
		return err
	}
	err = wallets.AddWallet(reconstructedWallet)
	if err != nil {
		return err
	}

	return nil
}

func KeyMachineBackupRemove(instructionData *instruction.DataFixed) ([]byte, error) {
	return nil, errors.New("WALLET KEY_MACHINE_BACKUP_REMOVE command not implemented yet")
}

func KeyCustodianBackup(instructionData *instruction.DataFixed) ([]byte, error) {
	return nil, errors.New("WALLET KEY_CUSTODIAN_BACKUP command not implemented yet")
}

func KeyCustodianRestore(instructionData *instruction.DataFixed) ([]byte, error) {
	return nil, errors.New("WALLET KEY_CUSTODIAN_RESTORE command not implemented yet")
}
