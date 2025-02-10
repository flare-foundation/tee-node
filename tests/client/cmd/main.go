package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"

	attestationv1 "tee-node/gen/go/attestation/v1"
	policyv1 "tee-node/gen/go/policy/v1"
	walletsv1 "tee-node/gen/go/wallets/v1"
	policyserver "tee-node/internal/policy"
	"tee-node/internal/requests"
	utilsserver "tee-node/internal/utils"
	"tee-node/internal/wallets"
	utils "tee-node/tests"
	"tee-node/tests/client/config"
	"tee-node/tests/client/policy"

	"github.com/alexflint/go-arg"
	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/database"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
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
	clientConn, err := utils.NewGRPCClient(config.Server.Host)
	if err != nil {
		log.Fatalf("failed to create client connection: %v", err)
	}
	defer clientConn.Close()

	ctx := context.Background()

	switch args.Call {
	case "generate_voters":
		var numVoters int
		if args.Arg1 == "" {
			numVoters = 3
		} else {
			numVoters, err = strconv.Atoi(args.Arg1)
			if err != nil {
				log.Fatalf("%v", err)
			}
		}
		voters, privKeys := utils.GenerateRandomVoters(numVoters)

		providers := &utils.Providers{Voters: voters, PrivKeys: privKeys}

		// Marshal Providers
		jsonStr, err := utils.MarshalProviders(providers)
		if err != nil {
			log.Fatalf("%v", err)
		}
		f, err := os.Create("tests/test_providers.json")
		if err != nil {
			log.Fatalf("%v", err)
		}
		_, err = f.Write(jsonStr)
		if err != nil {
			log.Fatalf("%v", err)
		}

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

		logger.Info("fetched and initialized policies")
	case "initial_policy_simulate":
		providersBytes, err := os.ReadFile("tests/test_providers.json")
		if err != nil {
			log.Fatalf("%v", err)
		}
		providers, err := utils.UnmarshalProviders(providersBytes)
		if err != nil {
			log.Fatalf("%v", err)
		}

		epochId, randSeed := uint32(1), int64(12345)
		initialPolicy := utils.GenerateRandomPolicyData(epochId, providers.Voters, randSeed)
		initialPolicyBytes, err := policyserver.EncodeSigningPolicy(&initialPolicy)
		if err != nil {
			log.Fatalf("%v", err)
		}

		hash := policyserver.SigningPolicyHash(initialPolicyBytes)
		fmt.Println(hex.EncodeToString(hash))

		numPolicies := 5
		policySignaturesArray, err := utils.GenerateRandomSignNewPolicyRequestArrays(epochId, randSeed, providers.Voters, providers.PrivKeys, numPolicies)
		if err != nil {
			log.Fatalf("could not generate random policy policy: %v", err)
		}

		req := &policyv1.InitializePolicyRequest{
			InitialPolicyBytes: initialPolicyBytes,
			NewPolicyRequests:  policySignaturesArray,
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

		var providerNum int
		if args.Arg1 == "" {
			providerNum = 0
		} else {
			providerNum, err = strconv.Atoi(args.Arg1)
			if err != nil {
				log.Fatalf("%v", err)
			}
		}
		providersBytes, err := os.ReadFile("tests/test_providers.json")
		if err != nil {
			log.Fatalf("%v", err)
		}
		providers, err := utils.UnmarshalProviders(providersBytes)
		if err != nil {
			log.Fatalf("%v", err)
		}
		providerPrivKey := providers.PrivKeys[providerNum]

		walletName := args.Arg2
		nonceBytes, err := utilsserver.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalf("%v", err)
		}

		newWalletRequest := wallets.NewNewWalletRequest(walletName)
		signature, err := requests.Sign(newWalletRequest, providerPrivKey)
		if err != nil {
			log.Fatalf("%v", err)
		}

		resp, err := walletClient.NewWallet(ctx, &walletsv1.NewWalletRequest{Name: walletName, Nonce: hex.EncodeToString(nonceBytes), Signature: signature})
		if err != nil {
			log.Fatalf("could not create a new wallet: %v", err)
		}

		logger.Infof("sent request to create wallet, is finalized %v, attestation token %s", resp.Finalized, resp.Token)

	case "pub_key":
		// Create a gRPC wallet client
		walletClient := walletsv1.NewWalletsServiceClient(clientConn)

		walletName := args.Arg1
		nonceBytes, err := utilsserver.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalf("%v", err)
		}

		pubKeyResp, err := walletClient.PublicKey(ctx, &walletsv1.PublicKeyRequest{Name: walletName, Nonce: hex.EncodeToString(nonceBytes)})
		if err != nil {
			log.Fatalf("could not create a new wallet: %v", err)
		}
		logger.Infof("public key: %s, attestation token %s", pubKeyResp.Address, pubKeyResp.Token)

	case "split_wallet":
		// Create a gRPC wallet client
		walletClient := walletsv1.NewWalletsServiceClient(clientConn)

		var providerNum int
		if args.Arg1 == "" {
			providerNum = 0
		} else {
			providerNum, err = strconv.Atoi(args.Arg1)
			if err != nil {
				log.Fatalf("%v", err)
			}
		}
		providersBytes, err := os.ReadFile("tests/test_providers.json")
		if err != nil {
			log.Fatalf("%v", err)
		}
		providers, err := utils.UnmarshalProviders(providersBytes)
		if err != nil {
			log.Fatalf("%v", err)
		}
		providerPrivKey := providers.PrivKeys[providerNum]

		walletName := args.Arg2
		nonceBytes, err := utilsserver.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalf("%v", err)
		}

		numBackups := len(config.Server.Backups)
		newSplitWalletRequest, err := wallets.NewSplitWalletRequest(walletName, make([]string, numBackups), config.Server.Backups, config.Server.BackupsThreshold)
		if err != nil {
			log.Fatalf("%v", err)
		}
		signature, err := requests.Sign(newSplitWalletRequest, providerPrivKey)
		if err != nil {
			log.Fatalf("%v", err)
		}

		resp, err := walletClient.SplitWallet(
			ctx,
			&walletsv1.SplitWalletRequest{
				Name:      walletName,
				TeeIds:    newSplitWalletRequest.IDs,
				Hosts:     newSplitWalletRequest.Hosts,
				Threshold: int64(newSplitWalletRequest.Threshold),
				Signature: signature,
				Nonce:     hex.EncodeToString(nonceBytes),
			},
		)
		if err != nil {
			log.Fatalf("could not create a new wallet: %v", err)
		}

		logger.Infof("sent request to split wallet, is finalized %v, attestation token %s", resp.Success, resp.Token)

	case "recover_wallet":
		// Create a gRPC wallet client
		walletClient := walletsv1.NewWalletsServiceClient(clientConn)

		var providerNum int
		if args.Arg1 == "" {
			providerNum = 0
		} else {
			providerNum, err = strconv.Atoi(args.Arg1)
			if err != nil {
				log.Fatalf("%v", err)
			}
		}
		providersBytes, err := os.ReadFile("tests/test_providers.json")
		if err != nil {
			log.Fatalf("%v", err)
		}
		providers, err := utils.UnmarshalProviders(providersBytes)
		if err != nil {
			log.Fatalf("%v", err)
		}
		providerPrivKey := providers.PrivKeys[providerNum]

		walletName := args.Arg2
		address := args.Arg3

		nonceBytes, err := utilsserver.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalf("%v", err)
		}

		numBackups := len(config.Server.Backups)

		shareIds := make([]string, numBackups)
		for i := range shareIds {
			shareIds[i] = strconv.Itoa(i + 1)
		}

		newRecoverWalletRequest, err := wallets.NewRecoverWalletRequest(walletName, make([]string, numBackups), config.Server.Backups, shareIds)
		if err != nil {
			log.Fatalf("%v", err)
		}
		signature, err := requests.Sign(newRecoverWalletRequest, providerPrivKey)
		if err != nil {
			log.Fatalf("%v", err)
		}

		resp, err := walletClient.RecoverWallet(
			ctx,
			&walletsv1.RecoverWalletRequest{
				Name:      walletName,
				TeeIds:    newRecoverWalletRequest.IDs,
				Hosts:     newRecoverWalletRequest.Hosts,
				Address:   address,
				Threshold: int64(config.Server.BackupsThreshold),
				Signature: signature,
				Nonce:     hex.EncodeToString(nonceBytes),
			},
		)
		if err != nil {
			log.Fatalf("could not create a new wallet: %v", err)
		}

		logger.Infof("sent request to recover wallet, is finalized %v, attestation token %s", resp.Success, resp.Token)

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
