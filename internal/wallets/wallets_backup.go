package wallets

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	api "tee-node/api/types"
	"tee-node/internal/attestation"
	"tee-node/internal/node"
	"tee-node/internal/requests"

	"github.com/pkg/errors"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/nacl/box"
)

var BackupWallets = InitBackupWalletsStorage()

type BackupWalletsStorage struct {
	Storage map[string]map[string]WalletShare

	sync.Mutex
}

func InitBackupWalletsStorage() BackupWalletsStorage {
	return BackupWalletsStorage{Storage: make(map[string]map[string]WalletShare)}
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
func SendShare(conn *websocket.Conn, share *WalletShare, outNodeId, pubKey string, instructionData *api.InstructionData, signatures [][]byte) error {
	myNode := node.GetNodeId()

	err := StartMutualAttestation(conn, myNode.Uuid, outNodeId)
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

	logger.Infof("sent a share for wallet %s", share.WalletName)

	return err
}

func GetShares(conn *websocket.Conn) error {
	myNode := node.GetNodeId()

	_, err := ReceiveMutualAttestation(conn, myNode.Uuid)
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

	BackupWallets.Lock()
	if _, ok := BackupWallets.Storage[walletShare.WalletName]; !ok {
		BackupWallets.Storage[walletShare.WalletName] = make(map[string]WalletShare)
	}
	BackupWallets.Storage[walletShare.WalletName][walletShare.Share.ID()] = walletShare
	BackupWallets.Unlock()
	logger.Infof("received a share for wallet %s, id %s", walletShare.WalletName, walletShare.Share.ID())

	return nil
}

type shareInfo struct {
	I               int
	InstructionData api.InstructionData
	Signatures      [][]byte
}

func (s shareInfo) Check(myNodeId, outNodeId string) error {
	requestCounter := requests.NewRequestCounter(s.InstructionData)
	requestPolicy, err := requestCounter.GetRequestPolicy()
	if err != nil {
		return err
	}

	for _, signature := range s.Signatures {
		providerAddress, err := requests.CheckSignature(s.InstructionData, signature, requestPolicy)
		if err != nil {
			return err
		}
		requestCounter.AddRequestSignature(providerAddress, signature)
	}

	thresholdReached := requestCounter.ThresholdReached(requestPolicy)
	if !thresholdReached {
		return errors.New("threshold not reached")
	}

	if outNodeId != s.InstructionData.TeeId {
		return errors.New("Requester's NodeId not matching instructions")
	}

	recoverWalletRequest, err := api.NewRecoverWalletRequest(&s.InstructionData)
	if err != nil {
		return err
	}
	if recoverWalletRequest.TeeIds[s.I] != myNodeId {
		return errors.New("My NodeId not matching instructions")
	}

	return nil
}

func (s shareInfo) Extract() (string, string, string) {
	recoverWalletRequest, _ := api.NewRecoverWalletRequest(&s.InstructionData) // error already checked before

	return recoverWalletRequest.Name, recoverWalletRequest.ShareIds[s.I], recoverWalletRequest.PublicKey

}

func RequestShare(conn *websocket.Conn, outNodeId string, i int, instructionData *api.InstructionData, signatures [][]byte) (*WalletShare, error) {
	myNode := node.GetNodeId()

	err := StartMutualAttestation(conn, myNode.Uuid, outNodeId)
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

	outNodeId, err := ReceiveMutualAttestation(conn, myNode.Uuid)
	if err != nil {
		return err
	}

	var shareInfo shareInfo
	err = conn.ReadJSON(&shareInfo)
	if err != nil {
		return err
	}

	err = shareInfo.Check(myNode.Uuid, outNodeId)
	if err != nil {
		return err
	}
	walletName, shareId, pubKey := shareInfo.Extract()

	BackupWallets.Lock()
	walletShares, ok := BackupWallets.Storage[walletName]
	if !ok {
		BackupWallets.Unlock()
		return errors.New("no backup share of wallet with given name")
	}
	walletShare, ok := walletShares[shareId]
	if !ok {
		BackupWallets.Unlock()
		return errors.New("no backup share of wallet with given Id")
	}
	BackupWallets.Unlock()

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

	logger.Infof("provided a share for wallet %s", walletShare.WalletName)

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
