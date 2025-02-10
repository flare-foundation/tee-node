package walletsservice

import (
	"net/http"
	"tee-node/internal/wallets"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/gorilla/websocket"
)

var WSUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func GetShares(w http.ResponseWriter, r *http.Request) {
	conn, err := WSUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	walletShare := wallets.WalletShare{}

	err = conn.ReadJSON(&walletShare)
	if err != nil {
		conn.Close()
		return
	}

	if _, ok := wallets.BackupWallets[walletShare.WalletName]; !ok {
		wallets.BackupWallets[walletShare.WalletName] = make(map[string]wallets.WalletShare)
	}
	wallets.BackupWallets[walletShare.WalletName][walletShare.Share.ID()] = walletShare
	logger.Infof("received a share for wallet %s, id %s", walletShare.WalletName, walletShare.Share.ID())

	conn.Close()
}

func SendShare(conn *websocket.Conn, share *wallets.WalletShare) error {
	err := conn.WriteJSON(share)

	logger.Infof("sent a share for wallet %s", share.WalletName)

	return err
}

type shareInfo struct {
	WalletName string
	Id         string
}

func RecoverShare(w http.ResponseWriter, r *http.Request) {
	conn, err := WSUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	shareInfo := shareInfo{}
	err = conn.ReadJSON(&shareInfo)
	if err != nil {
		conn.Close()
		return
	}

	walletShares, ok := wallets.BackupWallets[shareInfo.WalletName]
	if !ok {
		conn.Close()
		return
	}
	walletShare, ok := walletShares[shareInfo.Id]
	if !ok {
		conn.Close()
		return
	}

	err = conn.WriteJSON(walletShare)
	if err != nil {
		conn.Close()
		return
	}
	logger.Infof("provided a share for wallet %s", walletShare.WalletName)

	conn.Close()
}

func RequestShare(conn *websocket.Conn, walletName, shareId string) (*wallets.WalletShare, error) {
	shareInfo := shareInfo{WalletName: walletName, Id: shareId}
	err := conn.WriteJSON(shareInfo)
	if err != nil {
		conn.Close()
		return nil, err
	}
	walletShare := wallets.WalletShare{}
	err = conn.ReadJSON(&walletShare)
	if err != nil {
		conn.Close()
		return nil, err
	}

	logger.Infof("obtained a share for wallet %s", walletShare.WalletName)

	return &walletShare, nil
}
