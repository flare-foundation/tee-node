package walletsservice

import (
	"encoding/hex"

	"github.com/google/logger"
	"github.com/pkg/errors"

	"fmt"
	api "tee-node/api/types"
	"tee-node/internal/attestation"
	"tee-node/internal/node"
	"tee-node/internal/utils"
	"tee-node/internal/wallets"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gorilla/websocket"
)

func NewWallet(instructionData *api.InstructionData) error {
	newWalletRequest, err := api.ParseNewWalletRequest(instructionData)
	if err != nil {
		return err
	}

	err = wallets.CreateNewWallet(newWalletRequest.Name)
	if err != nil {
		return err
	}

	return nil
}

func DeleteWallet(instructionData *api.InstructionData) error {
	delWalletRequest, err := api.NewDeleteWalletRequest(instructionData)
	if err != nil {
		return err
	}

	wallets.RemoveWallet(delWalletRequest.Name)

	return nil
}

func SplitWallet(instructionData *api.InstructionData, signatures [][]byte) error {
	splitWalletRequest, err := api.NewSplitWalletRequest(instructionData)
	if err != nil {
		return err
	}
	numShares := len(splitWalletRequest.TeeIds)

	splits, err := wallets.SplitWalletByName(splitWalletRequest.Name, numShares, int(splitWalletRequest.Threshold))
	if err != nil {
		return err
	}

	wsConns := make([]*websocket.Conn, numShares)
	for i, hostURL := range splitWalletRequest.Hosts {
		// Create a new WebSocket connection
		wsConns[i], _, err = websocket.DefaultDialer.Dial(hostURL+"/share_wallet", nil) // todo timeout
		if err != nil {
			return err
		}
	}

	// todo attest others, itd.
	for i, conn := range wsConns {
		err = wallets.SendShare(conn, splits[i], splitWalletRequest.TeeIds[i], splitWalletRequest.PublicKeys[i], instructionData, signatures)
		if err != nil {
			return err
		}
		conn.Close()
	}

	return nil
}

func RecoverWallet(instructionData *api.InstructionData, signatures [][]byte) error {
	recoverWalletRequest, err := api.NewRecoverWalletRequest(instructionData)
	if err != nil {
		return err
	}

	// TODO: I moved this check here, but if we think it should happen before ProcessRequest, we can move it back
	myNode := node.GetNodeId()
	if hex.EncodeToString(myNode.EncryptionKey.PublicKey[:]) != recoverWalletRequest.PublicKey {
		return errors.New("public key not matching node's public key")
	}

	numShares := len(recoverWalletRequest.TeeIds)

	wsConns := make([]*websocket.Conn, numShares)
	for i, hostURL := range recoverWalletRequest.Hosts {
		// Create a new WebSocket connection
		wsConns[i], _, err = websocket.DefaultDialer.Dial(hostURL+"/recover_wallet", nil) // todo timeout
		if err != nil {
			return err
		}
	}
	// todo send splits, attest others, itd.
	splits := make([]*wallets.WalletShare, 0)
	for i, conn := range wsConns {
		share, err := wallets.RequestShare(
			conn,
			recoverWalletRequest.TeeIds[i],
			i,
			instructionData,
			signatures,
		)
		if err != nil {
			return err
		}
		splits = append(splits, share)

		logger.Infof("obtained a share for wallet %s", recoverWalletRequest.Name)

		conn.Close()
	}

	address := common.HexToAddress(recoverWalletRequest.Address)
	reconstructedWallet, err := wallets.JointWallet(splits, recoverWalletRequest.Name, address, int(recoverWalletRequest.Threshold))
	if err != nil {
		return err
	}
	err = wallets.AddWallet(reconstructedWallet)
	if err != nil {
		return err
	}

	return nil
}

func KeyMachineBackupRemove(instructionData *api.InstructionData) ([]byte, error) {
	return nil, errors.New("WALLET KEY_MACHINE_BACKUP_REMOVE command not implemented yet")
}

func KeyCustodianBackup(instructionData *api.InstructionData) ([]byte, error) {
	return nil, errors.New("WALLET KEY_CUSTODIAN_BACKUP command not implemented yet")
}

func KeyCustodianRestore(instructionData *api.InstructionData) ([]byte, error) {
	return nil, errors.New("WALLET KEY_CUSTODIAN_RESTORE command not implemented yet")
}

// GETERS

func WalletInfo(req *api.WalletInfoRequest) (*api.WalletInfoResponse, error) {
	ethAddress, err := wallets.GetEthAddress(req.Name)
	publicKey, err2 := wallets.GetPublicKey(req.Name)

	fmt.Println("ethAddress", ethAddress)
	fmt.Println("publicKey", publicKey)
	if err != nil || err2 != nil {
		return nil, fmt.Errorf("wallet non-existent")
	}

	xrpAddress, err := wallets.GetXrpAddress(req.Name)
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
