package walletsservice

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"tee-node/config"
	"tee-node/internal/attestation"
	"tee-node/internal/node"
	"tee-node/internal/wallets"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/nacl/box"
)

var WSUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

type AttestationRequest struct {
	Nonce  string
	NodeId string // todo: it should be signed by data providers
}

type AttestationResponse struct {
	Token string
	Nonce string
}

func SendShare(conn *websocket.Conn, share *wallets.WalletShare, outNodeId, pubKey string) error {
	myNode := node.GetNodeId()

	if config.Mode == 0 {
		err := StartMutualAttestation(conn, myNode.Uuid, outNodeId)
		if err != nil {
			return err
		}
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

func GetShares(w http.ResponseWriter, r *http.Request) {
	conn, err := WSUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	myNode := node.GetNodeId()

	if config.Mode == 0 {
		err = ReceiveMutualAttestation(conn, myNode.Uuid)
		if err != nil {
			return
		}
	}

	_, encryptedMsg, err := conn.ReadMessage()
	if err != nil {
		return
	}

	shareBytes, ok := box.OpenAnonymous(nil, encryptedMsg, &myNode.EncryptionKey.PublicKey, &myNode.EncryptionKey.PrivateKey)
	if !ok {
		return
	}

	walletShare := wallets.WalletShare{}
	err = json.Unmarshal(shareBytes, &walletShare)
	if err != nil {
		return
	}

	wallets.BackupWallets.Lock()
	if _, ok := wallets.BackupWallets.Storage[walletShare.WalletName]; !ok {
		wallets.BackupWallets.Storage[walletShare.WalletName] = make(map[string]wallets.WalletShare)
	}
	wallets.BackupWallets.Storage[walletShare.WalletName][walletShare.Share.ID()] = walletShare
	wallets.BackupWallets.Unlock()
	logger.Infof("received a share for wallet %s, id %s", walletShare.WalletName, walletShare.Share.ID())
}

type shareInfo struct {
	WalletName string
	Id         string
	PubKey     string // todo: it should be signed by data providers
}

func RequestShare(conn *websocket.Conn, walletName, shareId, outNodeId string) (*wallets.WalletShare, error) {
	myNode := node.GetNodeId()

	if config.Mode == 0 {
		err := StartMutualAttestation(conn, myNode.Uuid, outNodeId)
		if err != nil {
			return nil, err
		}
	}

	shareInfo := shareInfo{WalletName: walletName, Id: shareId, PubKey: hex.EncodeToString(myNode.EncryptionKey.PublicKey[:])}
	err := conn.WriteJSON(shareInfo)
	if err != nil {
		conn.Close()
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

	walletShare := wallets.WalletShare{}
	err = json.Unmarshal(shareBytes, &walletShare)
	if err != nil {
		return nil, err
	}

	logger.Infof("obtained a share for wallet %s", walletShare.WalletName)

	return &walletShare, nil
}

func RecoverShare(w http.ResponseWriter, r *http.Request) {
	conn, err := WSUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	myNode := node.GetNodeId()

	if config.Mode == 0 {
		err := ReceiveMutualAttestation(conn, myNode.Uuid)
		if err != nil {
			return
		}
	}

	shareInfo := shareInfo{}
	err = conn.ReadJSON(&shareInfo)
	if err != nil {
		conn.Close()
		return
	}

	wallets.BackupWallets.Lock()
	walletShares, ok := wallets.BackupWallets.Storage[shareInfo.WalletName]
	if !ok {
		conn.Close()
		return
	}
	walletShare, ok := walletShares[shareInfo.Id]
	if !ok {
		conn.Close()
		return
	}
	wallets.BackupWallets.Unlock()

	shareBytes, err := json.Marshal(walletShare)
	if err != nil {
		conn.Close()
		return
	}
	pubKeyBytes, err := hex.DecodeString(shareInfo.PubKey)
	if err != nil {
		conn.Close()
		return
	}
	pk := [32]byte(pubKeyBytes)

	encrypted, err := box.SealAnonymous(nil, shareBytes, &pk, rand.Reader)
	if err != nil {
		conn.Close()
		return
	}

	err = conn.WriteMessage(websocket.TextMessage, encrypted)
	if err != nil {
		conn.Close()
		return
	}

	logger.Infof("provided a share for wallet %s", walletShare.WalletName)

	conn.Close()
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
	token, err := attestation.ValidatePKIToken(*attestation.GoogleCert, attResp.Token)
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

func ReceiveMutualAttestation(conn *websocket.Conn, myId string) error {
	attReq := AttestationRequest{}
	err := conn.ReadJSON(&attReq)
	if err != nil {
		return err
	}

	tokeBytes, err := attestation.GetGoogleAttestationToken([]string{attReq.Nonce, myId}, attestation.PKITokenType)
	if err != nil {
		return err
	}
	nonce := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return err
	}
	err = conn.WriteJSON(&AttestationResponse{Token: string(tokeBytes), Nonce: string(nonce)})
	if err != nil {
		return err
	}

	attResp := AttestationResponse{}
	err = conn.ReadJSON(&attResp)
	if err != nil {
		return err
	}
	token, err := attestation.ValidatePKIToken(*attestation.GoogleCert, attResp.Token)
	if err != nil {
		return err
	}
	ok, _ := attestation.ValidateClaims(token, []string{string(nonce), attReq.NodeId})
	if !ok {
		return err
	}

	return nil
}
