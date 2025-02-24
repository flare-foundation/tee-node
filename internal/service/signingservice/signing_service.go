package signingservice

import (
	"context"

	api "tee-node/api/types"
	"tee-node/config"
	"tee-node/internal/attestation"
	"tee-node/internal/requests"
	"tee-node/internal/signing"
	"tee-node/internal/utils"
	"tee-node/internal/wallets"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service struct {
}

func NewService() *Service {
	return &Service{}
}

func (s *Service) SignPaymentTransaction(ctx context.Context, req *api.SignPaymentTransactionRequest) (*api.ResponseMessage, error) {

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "request cancelled")
	default:
	}

	if !wallets.WalletExists(req.WalletName) {
		return nil, status.Error(codes.NotFound, "wallet not found")
	}

	signPaymentRequest, err := signing.NewSignPaymentRequest(req.WalletName, req.PaymentHash)
	if err != nil {
		return nil, err
	}

	requestCounter, thresholdReached, err := requests.ProcessRequest(signPaymentRequest, req.Signature, &requests.SignPaymentRequestsStorage)
	if err != nil {
		return nil, err
	}

	if thresholdReached && !requestCounter.Done {
		signingWallet, err := wallets.GetWallet(req.WalletName)
		if err != nil {
			return nil, err
		}

		txnSignature, err := signing.SignXrpPayment(req.PaymentHash, signingWallet.PrivateKey)
		if err != nil {
			return nil, err
		}

		requestCounter.Result = txnSignature
		requestCounter.Done = true
	}

	// Get the attestation token
	nonces := []string{req.Challenge, requestCounter.Request.Message()}
	var tokenBytes []byte
	if config.Mode == 0 {
		tokenBytes, err = attestation.GetGoogleAttestationToken(nonces, attestation.OIDCTokenType)
		if err != nil {
			return nil, err
		}
	}

	return &api.ResponseMessage{Message: "Success", ThresholdReached: thresholdReached, Token: string(tokenBytes)}, nil
}

func (s *Service) GetPaymentSignature(ctx context.Context, req *api.GetPaymentSignatureRequest) (*api.GetPaymentSignatureResponse, error) {

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "request cancelled")
	default:
	}

	if !wallets.WalletExists(req.WalletName) {
		return nil, status.Error(codes.NotFound, "wallet not found")
	}

	signPaymentRequest, err := signing.NewSignPaymentRequest(req.WalletName, req.PaymentHash)
	if err != nil {
		return nil, err
	}

	requests.SignPaymentRequestsStorage.Lock()
	requestCounter, ok := requests.SignPaymentRequestsStorage.Storage[signPaymentRequest.Message()]
	requests.SignPaymentRequestsStorage.Unlock()
	if !ok {
		return nil, status.Error(codes.NotFound, "request not found")
	}

	if !requestCounter.Done {
		return nil, status.Error(codes.NotFound, "request uncompleted")
	}

	signingWallet, err := wallets.GetWallet(req.WalletName)
	if err != nil {
		return nil, err
	}

	// Get the attestation token
	nonces := []string{req.Challenge, requestCounter.Request.Message()}
	var tokenBytes []byte
	if config.Mode == 0 {
		tokenBytes, err = attestation.GetGoogleAttestationToken(nonces, attestation.OIDCTokenType)
		if err != nil {
			return nil, err
		}
	}

	xrpAccountAddress, _ := wallets.GetXrpAddress(req.WalletName)
	signingPubKey := utils.SerializeCompressed(&signingWallet.PrivateKey.PublicKey)

	return &api.GetPaymentSignatureResponse{Account: xrpAccountAddress, TxnSignature: requestCounter.Result, SigningPubKey: signingPubKey, Token: string(tokenBytes)}, nil
}
