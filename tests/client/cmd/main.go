package main

import (
	"context"
	"log"
	"time"

	attestationv1 "tee-node/gen/go/attestation/v1"
	policyv1 "tee-node/gen/go/policy/v1"
	walletsv1 "tee-node/gen/go/wallets/v1"
	"tee-node/tests/client/config"
	"tee-node/tests/client/policy"

	"github.com/alexflint/go-arg"
	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/database"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

const GCP_INSTANCE_IP = "localhost"

var args struct {
	Call   string
	Arg1   string
	Arg2   string
	Arg3   string
	Config string `default:"config.toml"`
}

// TODO: make cli configurable calls
func main() {
	arg.MustParse(&args)

	config, err := config.ReadConfig(args.Config)
	if err != nil {
		log.Fatalf("failed to read config: %v", err)
	}

	// Create a connection to the server using grpc.NewClient
	clientConn, err := NewGRPCClient(config.Server.Host)
	if err != nil {
		log.Fatalf("failed to create client connection: %v", err)
	}
	defer clientConn.Close()

	ctx := context.Background()

	switch args.Call {
	case "initial_policy":
		db, err := database.Connect(&config.DB)
		if err != nil {
			log.Fatalf("failed to connect to DB: %v", err)
		}
		params := policy.PolicyHistoryParams{RelayContractAddress: common.HexToAddress(config.Chain.RelayContractAddress), FlareSystemManagerContractAddress: common.HexToAddress(config.Chain.FlareSystemManagerContractAddress)}

		policies, signatures, err := policy.FetchPolicyHistory(ctx, &params, db)
		if err != nil {
			log.Fatalf("could not fetch policy: %v", err)
		}
		req, err := policy.CreateSigningRequest(policies, signatures)
		if err != nil {
			log.Fatalf("could not create signing request: %v", err)
		}

		// Create a gRPC wallet client
		policyClient := policyv1.NewPolicyServiceClient(clientConn)

		_, err = policyClient.InitializePolicy(ctx, req)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		logger.Info("initialized policies")
	case "new_wallet":
		// Create a gRPC wallet client
		walletClient := walletsv1.NewWalletsServiceClient(clientConn)

		walletName := args.Arg1
		nonce := args.Arg2
		resp, err := walletClient.NewWallet(ctx, &walletsv1.NewWalletRequest{Name: walletName, Nonce: nonce})
		if err != nil {
			log.Fatalf("could not create a new wallet: %v", err)
		}

		logger.Infof("created a wallet, attestation token %s", resp.Token)

	case "pub_key":
		// Create a gRPC wallet client
		walletClient := walletsv1.NewWalletsServiceClient(clientConn)

		walletName := args.Arg1
		nonce := args.Arg2
		pubKeyResp, err := walletClient.PublicKey(ctx, &walletsv1.PublicKeyRequest{Name: walletName, Nonce: nonce})
		if err != nil {
			log.Fatalf("could not create a new wallet: %v", err)
		}
		logger.Infof("public key: %s, attestation token %s", pubKeyResp.Address, pubKeyResp.Token)

	case "hardware_attestation":
		attestationClient := attestationv1.NewAttestationServiceClient(clientConn)

		nonce := args.Arg1
		hardwareResp, err := attestationClient.GetHardwareAttestation(ctx, &attestationv1.GetHardwareAttestationRequest{
			Nonce: nonce,
		})
		if err != nil {
			log.Fatalf("could not sign: %v", err)
		}

		log.Printf("Hardware Attestation response: %v", hardwareResp.JsonAttestation)

	default:
		logger.Warn("call not recognized")
	}

}

func NewGRPCClient(target string) (*grpc.ClientConn, error) {
	// Create slice for dial options
	var opts []grpc.DialOption

	// 1. Basic options
	opts = append(opts,
		grpc.WithTransportCredentials(insecure.NewCredentials()), // Only for development
		grpc.WithIdleTimeout(60*time.Second),                     // Idle timeout (close connection if idle)
		grpc.WithUnaryInterceptor(ClientLoggingInterceptor),      // Log requests
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                10 * time.Second, // send pings every 10 seconds if there is no activity
			Timeout:             5 * time.Second,  // wait 5 seconds for ping response
			PermitWithoutStream: true,             // allow pings even without active streams
		}),
		grpc.WithDefaultServiceConfig(`{  
            "methodConfig": [{  
                 "name": [  
                {"service": "signing.SigningService"},  
                {"service": "attestation.AttestationService"}  
            ],  
                "waitForReady": true,  
                "retryPolicy": {  
                    "MaxAttempts": 3,  
                    "InitialBackoff": "0.1s",  
                    "MaxBackoff": "1s",  
                    "BackoffMultiplier": 2.0,  
                    "RetryableStatusCodes": ["UNAVAILABLE"]  
                }  
            }]  
        }`), // Retry policy
	)

	// Connect to the server
	return grpc.NewClient(target, opts...)
}

// ClientLoggingInterceptor logs client requests
func ClientLoggingInterceptor(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	start := time.Now()
	err := invoker(ctx, method, req, reply, cc, opts...)
	log.Printf("method: %s, duration: %v, error: %v", method, time.Since(start), err)
	return err
}
