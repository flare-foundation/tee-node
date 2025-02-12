package walletsservice

import (
	"context"
	api "tee-node/api/types"
	"tee-node/config"
	"tee-node/internal/attestation"
	"tee-node/internal/requests"
	"tee-node/internal/wallets"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gorilla/websocket"
)

type Service struct {
}

// NewService creates a new signing service
func NewService() *Service {
	return &Service{}
}

func (s *Service) NewWallet(ctx context.Context, req *api.NewWalletRequest) (*api.NewWalletResponse, error) {
	walletRequest := wallets.NewNewWalletRequest(req.Name)
	requestCounter, thresholdReached, err := requests.ProcessRequest(walletRequest, req.Signature, requests.NewWalletRequestsStorage)
	if err != nil {
		return nil, err
	}

	if thresholdReached && !requestCounter.Done {
		_, err = wallets.CreateNewWallet(requestCounter.Request.Name)
		if err != nil {
			return nil, err
		}
		requestCounter.Done = true
	}

	nonces := []string{req.Nonce, requestCounter.Request.Message()}
	var tokenBytes []byte
	if config.Mode == 0 {
		tokenBytes, err = attestation.GetGoogleAttestationToken(nonces)
		if err != nil {
			return nil, err
		}
	}

	return &api.NewWalletResponse{
		Finalized: thresholdReached,
		Token:     string(tokenBytes),
	}, nil
}

func (s *Service) DeleteWallet(ctx context.Context, req *api.NewWalletRequest) (*api.NewWalletResponse, error) {
	walletRequest := wallets.NewDeleteWalletRequest(req.Name)
	requestCounter, thresholdReached, err := requests.ProcessRequest(walletRequest, req.Signature, requests.DeleteWalletRequestsStorage)
	if err != nil {
		return nil, err
	}

	if thresholdReached && !requestCounter.Done {
		wallets.RemoveWallet(requestCounter.Request.Name)
		requestCounter.Done = true
	}

	nonces := []string{req.Nonce, requestCounter.Request.Message()}
	var tokenBytes []byte
	if config.Mode == 0 {
		tokenBytes, err = attestation.GetGoogleAttestationToken(nonces)
		if err != nil {
			return nil, err
		}
	}

	return &api.NewWalletResponse{
		Finalized: thresholdReached,
		Token:     string(tokenBytes),
	}, nil
}

func (s *Service) PublicKey(ctx context.Context, req *api.PublicKeyRequest) (*api.PublicKeyResponse, error) {
	address, err := wallets.GetPublicKey(req.Name)
	if err != nil {
		return nil, err
	}

	nonces := []string{req.Nonce, "PublicKey", address}

	var tokenBytes []byte
	if config.Mode == 0 {
		tokenBytes, err = attestation.GetGoogleAttestationToken(nonces)
		if err != nil {
			return nil, err
		}
	}

	return &api.PublicKeyResponse{
		Address: address,
		Token:   string(tokenBytes),
	}, nil
}

func (s *Service) SplitWallet(ctx context.Context, req *api.SplitWalletRequest) (*api.SplitWalletResponse, error) {
	splitWalletRequest, err := wallets.NewSplitWalletRequest(req.Name, req.TeeIds, req.Hosts, int(req.Threshold))
	if err != nil {
		return nil, err
	}
	requestCounter, thresholdReached, err := requests.ProcessRequest(splitWalletRequest, req.Signature, requests.SplitWalletRequestsStorage)
	if err != nil {
		return nil, err
	}

	if thresholdReached && !requestCounter.Done {
		splits, err := wallets.SplitWalletByName(requestCounter.Request.Name, requestCounter.Request.NumShares, requestCounter.Request.Threshold)
		if err != nil {
			return nil, err
		}

		wsConns := make([]*websocket.Conn, requestCounter.Request.NumShares)
		for i, hostURL := range req.Hosts {
			// Create a new WebSocket connection
			wsConns[i], _, err = websocket.DefaultDialer.Dial(hostURL+"/share_wallet", nil) // todo timeout
			if err != nil {
				return nil, err
			}
		}
		// todo attest others, itd.
		for i, conn := range wsConns {
			err = SendShare(conn, splits[i])
			if err != nil {
				return nil, err
			}
			conn.Close()
		}

		requestCounter.Done = true
	}

	nonces := []string{req.Nonce, requestCounter.Request.Message()}
	var tokenBytes []byte
	if config.Mode == 0 {
		tokenBytes, err = attestation.GetGoogleAttestationToken(nonces)
		if err != nil {
			return nil, err
		}
	}

	return &api.SplitWalletResponse{
		Finalized: requestCounter.Done,
		Token:     string(tokenBytes),
	}, nil
}

func (s *Service) RecoverWallet(ctx context.Context, req *api.RecoverWalletRequest) (*api.RecoverWalletResponse, error) {
	recoverWalletRequest, err := wallets.NewRecoverWalletRequest(req.Name, req.TeeIds, req.Hosts, req.ShareIds)
	if err != nil {
		return nil, err
	}
	requestCounter, thresholdReached, err := requests.ProcessRequest(recoverWalletRequest, req.Signature, requests.RecoverWalletRequestsStorage)
	if err != nil {
		return nil, err
	}

	if thresholdReached && !requestCounter.Done {
		wsConns := make([]*websocket.Conn, requestCounter.Request.NumShares)
		for i, hostURL := range req.Hosts {
			// Create a new WebSocket connection
			wsConns[i], _, err = websocket.DefaultDialer.Dial(hostURL+"/recover_wallet", nil) // todo timeout
			if err != nil {
				return nil, err // todo: just skip
			}
		}
		// todo send splits, attest others, itd.
		splits := make([]*wallets.WalletShare, 0)
		for i, conn := range wsConns {
			share, err := RequestShare(conn, req.Name, req.ShareIds[i])
			if err != nil {
				return nil, err // todo: just skip
			}
			splits = append(splits, share)

			conn.Close()
		}
		reconstructedWallet, err := wallets.JointWallet(splits, req.Name, common.HexToAddress(req.Address), int(req.Threshold))
		if err != nil {
			return nil, err
		}
		err = wallets.AddWallet(reconstructedWallet)
		if err != nil {
			return nil, err
		}

		requestCounter.Done = true
	}

	nonces := []string{req.Nonce, requestCounter.Request.Message()}
	var tokenBytes []byte
	if config.Mode == 0 {
		tokenBytes, err = attestation.GetGoogleAttestationToken(nonces)
		if err != nil {
			return nil, err
		}
	}

	return &api.RecoverWalletResponse{
		Finalized: requestCounter.Done,
		Token:     string(tokenBytes),
	}, nil
}
