package wallets

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	api "tee-node/api/types"
	"tee-node/pkg/attestation"
	"tee-node/pkg/node"
	"tee-node/pkg/requests"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/nacl/box"
)

var backupWalletsStorage = InitBackupWalletsStorage()

type BackupWalletsStorage struct {
	// walletId to ShareId to WalletShare
	Storage map[BackupWalletKeyIdTriple]map[string]WalletShare

	sync.Mutex
}

type BackupWalletKeyIdTriple struct {
	BackupId string
	WalletId string
	KeyId    string
}

func InitBackupWalletsStorage() BackupWalletsStorage {
	return BackupWalletsStorage{Storage: make(map[BackupWalletKeyIdTriple]map[string]WalletShare)}
}

type AttestationRequest struct {
	Nonce  string
	NodeId string // todo: it should be signed by data providers
}

type AttestationResponse struct {
	Token string
	Nonce string
}

// todo: Add instruction and signatures check also by receiving nodes? at least code version of the receiving nodes?
func SendShare(conn *websocket.Conn, share *WalletShare, outNodeId, pubKey string, instructionData *instruction.DataFixed, signatures [][]byte) error {
	myNode := node.GetNodeId()

	err := StartMutualAttestation(conn, myNode.Id, outNodeId)
	if err != nil {
		return err
	}

	shareBytes, err := json.Marshal(share)
	if err != nil {
		return err
	}

	pubKeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return err
	}
	pk := [32]byte(pubKeyBytes)

	encrypted, err := box.SealAnonymous(nil, shareBytes, &pk, rand.Reader)
	if err != nil {
		return err
	}

	err = conn.WriteMessage(websocket.TextMessage, encrypted)
	if err != nil {
		return err
	}

	logger.Infof("sent a share for wallet %s", share.WalletId)

	return err
}

func GetShares(conn *websocket.Conn) error {
	myNode := node.GetNodeId()

	_, err := ReceiveMutualAttestation(conn, myNode.Id)
	if err != nil {
		return err
	}

	_, encryptedMsg, err := conn.ReadMessage()
	if err != nil {
		return err
	}

	shareBytes, ok := box.OpenAnonymous(nil, encryptedMsg, &myNode.EncryptionKey.PublicKey, &myNode.EncryptionKey.PrivateKey)
	if !ok {
		return errors.New("decryption failed")
	}

	walletShare := WalletShare{}
	err = json.Unmarshal(shareBytes, &walletShare)
	if err != nil {
		return err
	}

	backupIdTriple := BackupWalletKeyIdTriple{WalletId: walletShare.WalletId, KeyId: walletShare.KeyId, BackupId: walletShare.BackupId}

	backupWalletsStorage.Lock()
	if _, ok := backupWalletsStorage.Storage[backupIdTriple]; !ok {
		backupWalletsStorage.Storage[backupIdTriple] = make(map[string]WalletShare)
	}
	backupWalletsStorage.Storage[backupIdTriple][walletShare.Share.ID()] = walletShare
	backupWalletsStorage.Unlock()
	logger.Infof("received a share for wallet %s, id %s", walletShare.WalletId, walletShare.Share.ID())

	return nil
}

type shareInfo struct {
	I               int
	InstructionData instruction.DataFixed
	Signatures      [][]byte
}

func (s shareInfo) Check(myNodeId, outNodeId string) error {
	instructionData := &instruction.Data{DataFixed: s.InstructionData, AdditionalVariableMessage: []byte("")} // variable part is empty

	requestCounter := requests.NewRequestCounter(instructionData, common.Address{})
	for _, signature := range s.Signatures {
		providerAddress, err := requests.CheckSignature(instructionData, signature, requestCounter.RequestPolicy)
		if err != nil {
			return err
		}
		requestCounter.AddRequestSignature(providerAddress, signature)
	}

	thresholdReached := requestCounter.ThresholdReached()
	if !thresholdReached {
		return errors.New("threshold not reached")
	}

	if outNodeId != s.InstructionData.TeeID.String() {
		return errors.New("Requester's NodeId not matching instructions")
	}

	recoverWalletRequest, err := api.NewRecoverWalletRequest(&s.InstructionData)
	if err != nil {
		return err
	}
	if recoverWalletRequest.BackupTeeMachines[s.I].TeeId.String() != myNodeId {
		return errors.New("My NodeId not matching instructions")
	}

	return nil
}

func (s shareInfo) Extract() (BackupWalletKeyIdTriple, string, string) {
	recoverWalletRequest, _ := api.NewRecoverWalletRequest(&s.InstructionData) // error is already checked before
	var additionalFixedMessage api.RecoverWalletRequestAdditionalFixedMessage
	err := json.Unmarshal(s.InstructionData.AdditionalFixedMessage, &additionalFixedMessage)
	if err != nil {
		logger.Errorf("error unmarshalling additionalFixedMessage: %s", err)
	}

	return BackupWalletKeyIdTriple{BackupId: recoverWalletRequest.BackupId.String(), WalletId: hex.EncodeToString(recoverWalletRequest.WalletId[:]), KeyId: recoverWalletRequest.KeyId.String()},
		additionalFixedMessage.ShareIds[s.I], hex.EncodeToString(recoverWalletRequest.PublicKey[:])
}

func RequestShare(conn *websocket.Conn, outNodeId string, i int, instructionData *instruction.DataFixed, signatures [][]byte) (*WalletShare, error) {
	myNode := node.GetNodeId()

	err := StartMutualAttestation(conn, myNode.Id, outNodeId)
	if err != nil {
		return nil, err
	}

	shareInfo := shareInfo{
		I:               i,
		InstructionData: *instructionData,
		Signatures:      signatures,
	}
	err = conn.WriteJSON(shareInfo)
	if err != nil {
		return nil, err
	}

	_, encryptedMsg, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	shareBytes, ok := box.OpenAnonymous(nil, encryptedMsg, &myNode.EncryptionKey.PublicKey, &myNode.EncryptionKey.PrivateKey)
	if !ok {
		return nil, err
	}

	walletShare := WalletShare{}
	err = json.Unmarshal(shareBytes, &walletShare)
	if err != nil {
		return nil, err
	}

	return &walletShare, nil
}

func RecoverShare(conn *websocket.Conn) error {
	myNode := node.GetNodeId()

	outNodeId, err := ReceiveMutualAttestation(conn, myNode.Id)
	if err != nil {
		return err
	}

	var shareInfo shareInfo
	err = conn.ReadJSON(&shareInfo)
	if err != nil {
		return err
	}

	err = shareInfo.Check(myNode.Id, outNodeId)
	if err != nil {
		return err
	}
	backupIdTriple, shareId, pubKey := shareInfo.Extract()

	backupWalletsStorage.Lock()
	walletShares, ok := backupWalletsStorage.Storage[backupIdTriple]
	if !ok {
		backupWalletsStorage.Unlock()
		return errors.New("no backup share of wallet with given name")
	}
	walletShare, ok := walletShares[shareId]
	if !ok {
		backupWalletsStorage.Unlock()
		return errors.New("no backup share of wallet with given Id")
	}
	backupWalletsStorage.Unlock()

	shareBytes, err := json.Marshal(walletShare)
	if err != nil {
		return err
	}
	pubKeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return err
	}
	pk := [32]byte(pubKeyBytes)

	encrypted, err := box.SealAnonymous(nil, shareBytes, &pk, rand.Reader)
	if err != nil {
		return err
	}

	err = conn.WriteMessage(websocket.TextMessage, encrypted)
	if err != nil {
		return err
	}

	logger.Infof("provided a share for wallet %s", walletShare.WalletId)

	return nil
}

func StartMutualAttestation(conn *websocket.Conn, myNodeId, outNodeId string) error {
	nonce := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return fmt.Errorf("failed to create nonce: %w", err)
	}
	err = conn.WriteJSON(AttestationRequest{Nonce: string(nonce), NodeId: myNodeId})
	if err != nil {
		return err
	}

	attResp := AttestationResponse{}
	err = conn.ReadJSON(&attResp)
	if err != nil {
		return err
	}
	token, err := attestation.ValidatePKIToken(attestation.GoogleCert, attResp.Token)
	if err != nil {
		return err
	}

	ok, err := attestation.ValidateClaims(token, []string{string(nonce), outNodeId})
	if !ok {
		return err
	}

	tokenBytes, err := attestation.GetGoogleAttestationToken([]string{attResp.Nonce, myNodeId}, attestation.PKITokenType)
	if err != nil {
		return err
	}

	err = conn.WriteJSON(AttestationResponse{Token: string(tokenBytes)})
	if err != nil {
		return err
	}

	return nil
}

func ReceiveMutualAttestation(conn *websocket.Conn, myId string) (string, error) {
	attReq := AttestationRequest{}
	err := conn.ReadJSON(&attReq)
	if err != nil {
		return "", err
	}

	tokenBytes, err := attestation.GetGoogleAttestationToken([]string{attReq.Nonce, myId}, attestation.PKITokenType)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}
	err = conn.WriteJSON(&AttestationResponse{Token: string(tokenBytes), Nonce: string(nonce)})
	if err != nil {
		return "", err
	}

	attResp := AttestationResponse{}
	err = conn.ReadJSON(&attResp)
	if err != nil {
		return "", err
	}
	token, err := attestation.ValidatePKIToken(attestation.GoogleCert, attResp.Token)
	if err != nil {
		return "", err
	}
	ok, err := attestation.ValidateClaims(token, []string{string(nonce), attReq.NodeId})
	if !ok {
		return "", errors.Errorf("fail of validate %s", err)
	}

	return attReq.NodeId, nil
}
