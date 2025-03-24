package walletsservice

import (
	"encoding/hex"
	"encoding/json"

	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/google/logger"
	"github.com/pkg/errors"

	"fmt"
	api "tee-node/api/types"
	"tee-node/pkg/attestation"
	"tee-node/pkg/node"
	"tee-node/pkg/utils"
	"tee-node/pkg/wallets"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gorilla/websocket"
)

func NewWallet(instructionData *instruction.DataFixed) error {
	originalMessage, err := api.ParseNewWalletRequest(instructionData)
	if err != nil {
		return err
	}

	err = wallets.CreateNewWallet(wallets.WalletKeyIdPair{WalletId: hex.EncodeToString(originalMessage.WalletId[:]), KeyId: originalMessage.KeyId.String()})
	if err != nil {
		return err
	}

	return nil
}

func DeleteWallet(instructionData *instruction.DataFixed) error {
	delWalletRequest, err := api.NewDeleteWalletRequest(instructionData)
	if err != nil {
		return err
	}

	wallets.RemoveWallet(wallets.WalletKeyIdPair{WalletId: hex.EncodeToString(delWalletRequest.WalletId[:]), KeyId: delWalletRequest.KeyId.String()})

	return nil
}

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
		wallets.BackupWalletKeyIdTriple{BackupId: splitWalletRequest.BackupId.String(), WalletId: hex.EncodeToString(splitWalletRequest.WalletId[:]), KeyId: splitWalletRequest.KeyId.String()},
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

	// TODO: I moved this check here, but if we think it should happen before ProcessRequest, we can move it back
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
		wallets.BackupWalletKeyIdTriple{WalletId: hex.EncodeToString(recoverWalletRequest.WalletId[:]), KeyId: recoverWalletRequest.KeyId.String(), BackupId: recoverWalletRequest.BackupId.String()},
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

// GETERS

func WalletInfo(req *api.WalletInfoRequest) (*api.WalletInfoResponse, error) {
	walletKeyIdPair := wallets.WalletKeyIdPair{WalletId: req.WalletId, KeyId: req.KeyId}
	ethAddress, err := wallets.GetEthAddress(walletKeyIdPair)
	publicKey, err2 := wallets.GetPublicKey(walletKeyIdPair)
	if err != nil || err2 != nil {
		return nil, fmt.Errorf("wallet non-existent")
	}

	xrpAddress, err := wallets.GetXrpAddress(walletKeyIdPair)
	sec1PubKey := hex.EncodeToString(utils.SerializeCompressed(publicKey))
	if err != nil {
		return nil, fmt.Errorf("wallet non-existent")
	}

	nonces := []string{req.Challenge, "WalletInfo", ethAddress, xrpAddress}

	var tokenBytes []byte
	tokenBytes, err = attestation.GetGoogleAttestationToken(nonces, attestation.OIDCTokenType)
	if err != nil {
		return nil, err
	}

	return &api.WalletInfoResponse{
		EthAddress: ethAddress,
		EthPublicKey: api.ECDSAPublicKey{
			X: publicKey.X.String(),
			Y: publicKey.Y.String(),
		},
		XrpAddress:   xrpAddress,
		XrpPublicKey: sec1PubKey,
		Token:        string(tokenBytes),
	}, nil
}
