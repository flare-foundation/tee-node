package walletsservice

import (
	"context"
	"tee-node/config"
	pb "tee-node/gen/go/wallets/v1"
	"tee-node/internal/attestation"
	"tee-node/internal/wallets"
)

// Service implements the generated SigningServiceServer interface
type Service struct {
	// Embed the generated UnimplementedSigningServiceServer
	pb.UnimplementedWalletsServiceServer
	// Add any dependencies your service needs
}

// NewService creates a new signing service
func NewService() *Service {
	return &Service{}
}

// todo: add attestation, add signature check
func (s *Service) NewWallet(ctx context.Context, req *pb.NewWalletRequest) (*pb.NewWalletResponse, error) {
	check, address, err := wallets.ProcessNewWalletRequest(req.Name, req.Signature)
	if err != nil {
		return nil, err
	}

	if check {
		_, err = wallets.CreateNewWallet(req.Name)
		if err != nil {
			return nil, err
		}
	}

	nonces := []string{req.Nonce, "NewWallet", address}

	var tokenBytes []byte
	if config.Mode == 0 {
		tokenBytes, err = attestation.GetGoogleAttestationToken(nonces)
		if err != nil {
			return nil, err
		}
	}

	return &pb.NewWalletResponse{
		Finalized: check,
		Token:     string(tokenBytes),
	}, nil
}

func (s *Service) PublicKey(ctx context.Context, req *pb.PublicKeyRequest) (*pb.PublicKeyResponse, error) {
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

	return &pb.PublicKeyResponse{
		Address: address,
		Token:   string(tokenBytes),
	}, nil
}
