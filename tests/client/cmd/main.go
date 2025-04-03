package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"os"
	"strconv"

	api "tee-node/api/types"

	attestationserver "tee-node/pkg/attestation"
	policyserver "tee-node/pkg/policy"
	utilsserver "tee-node/pkg/utils"
	utils "tee-node/tests"

	"tee-node/tests/client/config"
	"tee-node/tests/client/policy"
	"tee-node/tests/client/xrpl"

	"github.com/ethereum/go-ethereum/accounts/abi"

	"github.com/alexflint/go-arg"
	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/database"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	commonpayment "github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
)

var args struct {
	Call          string
	Arg1          string
	Provider      int
	WalletId      string
	KeyId         string
	BackupId      string
	PubKey        string
	TeeId         string
	InstructionId string
	TeeIds        []string
	Address       string
	RewardEpochId uint32
	Config        string `default:"tests/configs/config_client.toml"`
}

// TODO: make cli configurable calls
func main() {
	arg.MustParse(&args)

	config, err := config.ReadConfig(args.Config)
	if err != nil {
		log.Fatalf("failed to read config: %v", err)
	}

	ctx := context.Background()
	nonceBytes, err := utilsserver.GenerateRandomBytes(32)
	if err != nil {
		log.Fatalf("%v", err)
	}

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
		voters, privKeys, _ := utils.GenerateRandomVoters(numVoters)

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
		params := &policy.PolicyHistoryParams{RelayContractAddress: common.HexToAddress(config.Chain.RelayContractAddress),
			FlareSystemManagerContractAddress: common.HexToAddress(config.Chain.FlareSystemManagerContractAddress),
			FlareVoterRegistryContractAddress: common.HexToAddress(config.Chain.FlareVoterRegistryContractAddress),
		}

		policies, signatures, err := policy.FetchPolicyHistory(ctx, params, db)
		if err != nil {
			log.Fatalf("could not fetch policy: %v", err)
		}
		activePolicyRewardEpoch := int(policies[len(policies)-1].RewardEpochId.Int64())
		minBlockNum, maxBlockNum, err := policy.FetchVoterRegisteredBlocksInfo(context.Background(), params, db, activePolicyRewardEpoch)
		if err != nil {
			log.Fatalf("could not fetch blocks info: %v", err)
		}
		pubKeysMap, err := policy.FetchVotersPublicKeysMap(context.Background(), params, db, minBlockNum, maxBlockNum, activePolicyRewardEpoch)
		if err != nil {
			log.Fatalf("could not fetch public keys: %v", err)
		}

		req, err := policy.CreateInitializePolicyRequest(policies, signatures, pubKeysMap)
		if err != nil {
			log.Fatalf("could not create signing request: %v", err)
		}

		_, err = utils.Post[api.InitializePolicyResponse](config.Server.Host+"/policies/initialize", req)
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
		pubKeys := make([]api.ECDSAPublicKey, len(providers.PrivKeys))
		for i, voter := range providers.PrivKeys {
			pubKeys[i] = api.ECDSAPublicKey{
				X: voter.PublicKey.X.String(),
				Y: voter.PublicKey.Y.String(),
			}
		}

		epochId, randSeed := uint32(1), int64(12345)
		initialPolicy := utils.GenerateRandomPolicyData(epochId, providers.Voters, randSeed)
		initialPolicyBytes, err := policyserver.EncodeSigningPolicy(&initialPolicy)
		if err != nil {
			log.Fatalf("%v", err)
		}

		numPolicies := 5
		policySignaturesArray, err := utils.GenerateRandomMultiSignedPolicyArray(epochId, randSeed, providers.Voters, providers.PrivKeys, numPolicies)
		if err != nil {
			log.Fatalf("could not generate random policy policy: %v", err)
		}

		req := &api.InitializePolicyRequest{
			InitialPolicyBytes:     initialPolicyBytes,
			NewPolicyRequests:      policySignaturesArray,
			LatestPolicyPublicKeys: pubKeys,
		}
		_, err = utils.Post[api.InitializePolicyResponse](config.Server.Host+"/policies/initialize", req)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		latestPolicy := req.NewPolicyRequests[len(req.NewPolicyRequests)-1]
		decodedPolicy, err := policyserver.DecodeSigningPolicy(latestPolicy.PolicyBytes)
		if err != nil {
			log.Fatalf("could not decode policy: %v", err)
		}
		logger.Infof("initialized policies. Active EpochID: %v", decodedPolicy.RewardEpochId)

	case "new_wallet":
		providerPrivKey, err := getProviderPrivKey(args.Provider)
		if err != nil {
			log.Fatalf("could not get provider private key: %v", err)
		}
		// TODO: keyId parameter should probably be big.Int or uint32
		keyIdParsed, err := strconv.ParseUint(args.KeyId, 10, 32)
		if err != nil {
			log.Fatalf("could not parse key id: %v", err)
		}

		originalMessage := wallet.ITeeWalletManagerKeyGenerate{
			TeeId:              common.HexToAddress(args.TeeId),
			WalletId:           common.HexToHash(args.WalletId),
			KeyId:              big.NewInt(int64(keyIdParsed)),
			OpType:             utilsserver.StringToOpHash("WALLET"),
			OpTypeConstants:    make([]byte, 0),
			AdminsPublicKeys:   make([]wallet.ITeeWalletManagerPublicKey, 0),
			AdminsThreshold:    big.NewInt(0),
			Cosigners:          make([]common.Address, 0),
			CosignersThreshold: big.NewInt(0),
		}
		originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[wallet.KeyGenerate]}.Pack(originalMessage)
		if err != nil {
			log.Fatalf("could not pack original message: %v", err)
		}

		instruction, err := utils.BuildMockInstruction("WALLET",
			"KEY_GENERATE",
			originalMessageEncoded,
			interface{}(nil),
			providerPrivKey,
			common.HexToAddress(args.TeeId),
			args.InstructionId,
			args.RewardEpochId,
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		resp, err := utils.Post[api.InstructionResponse](config.Server.Host+"/instruction", instruction)
		if err != nil {
			log.Fatalf("could not create a new wallet: %v", err)
		}

		logger.Infof("created a wallet: finalized:%v", resp.Finalized)

	case "pub_key":
		// TODO: Remove this function

		keyIdBig, err := strconv.ParseUint(args.KeyId, 10, 32)
		if err != nil {
			log.Fatalf("could not parse key id: %v", err)
		}

		req := &api.WalletInfoRequest{
			WalletId:  common.HexToHash(args.WalletId),
			KeyId:     big.NewInt(int64(keyIdBig)),
			Challenge: hex.EncodeToString(nonceBytes),
		}

		pubKeyResp, err := utils.Post[api.WalletInfoResponse](config.Server.Host+"/wallet", req)
		if err != nil {
			log.Fatalf("could not get a public key: %v", err)
		}
		logger.Infof("ethAddress: %s, public key: %s, attestation token %s", pubKeyResp.EthAddress, pubKeyResp.EthPublicKey.X, pubKeyResp.Token)

	case "wallet_info":
		nonceBytes, err := utilsserver.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalf("%v", err)
		}

		keyIdBig, err := strconv.ParseUint(args.KeyId, 10, 32)
		if err != nil {
			log.Fatalf("could not parse key id: %v", err)
		}

		req := &api.WalletInfoRequest{
			WalletId:  common.HexToHash(args.WalletId),
			KeyId:     big.NewInt(int64(keyIdBig)),
			Challenge: hex.EncodeToString(nonceBytes),
		}
		accInfoResp, err := utils.Post[api.WalletInfoResponse](config.Server.Host+"/wallet", req)
		if err != nil {
			log.Fatalf("could not get wallet info: %v", err)
		}
		logger.Infof("EthAddress: %s, XrpAddress: %s, PublicKey: %s, Attestation Token %s", accInfoResp.EthAddress, accInfoResp.XrpAddress, accInfoResp.XrpPublicKey, accInfoResp.Token)

	case "node_attestation":
		req := &api.GetNodeInfoRequest{Nonce: string(nonceBytes)}
		resp, err := utils.Post[api.GetNodeInfoResponse](config.Server.Host+"/info", req)
		if err != nil {
			log.Fatalf("could not get attestation: %v", err)
		}

		teeId := resp.Data.Id
		pubKey := resp.Data.EncryptionPublicKey

		logger.Infof("TeeId: %v PubKey: %v\n", teeId, pubKey)
		logger.Infof("node info: %v", resp.Data)

		if resp.Token != "magic_pass" {
			cert, err := attestationserver.LoadRootCert("google_confidential_space_root.crt")
			if err != nil {
				log.Fatalf("could not load certificate: %v", err)
			}
			token, err := attestationserver.ValidatePKIToken(cert, resp.Token)
			if err != nil {
				log.Fatalf("failed validating PKI token: %v", err)
			}

			hash, err := resp.Data.Hash()
			if err != nil {
				log.Fatalf("failed validating PKI token: %v", err)
			}
			ok, err := attestationserver.ValidateClaims(token, []string{string(nonceBytes), "GetNodeInfo", hash})
			if err != nil || !ok {
				log.Fatalf("failed validating PKI token: %v", err)
			}
		} else {
			logger.Infof("no token")
		}

	case "hash_payment":
		// ---------- Parse arguments ---------- //

		type PaymentFields struct {
			Amount             uint64 `json:"amount"`
			Fee                uint64 `json:"fee"`
			SpenderAccount     string `json:"spenderAccount"`
			DestinationAccount string `json:"destinationAccount"`
			Sequence           uint32 `json:"sequence"`
			LastLedgerSeq      uint32 `json:"lastLedgerSeq"`
			SignerAddress      string `json:"signerAddress"`
		}

		// Unmarshal JSON
		var paymentFields PaymentFields
		err = json.Unmarshal([]byte(args.Arg1), &paymentFields)
		if err != nil {
			log.Fatalf("Failed to parse JSON: %v", err)
		}

		// ---------- Encode and Hash the transaction ---------- //

		payment, err := xrpl.ConstructPaymentTransaction(paymentFields.Amount,
			paymentFields.Fee,
			paymentFields.SpenderAccount,
			paymentFields.DestinationAccount,
			paymentFields.Sequence,
			paymentFields.LastLedgerSeq)
		if err != nil {
			log.Fatalf("could not construct payment transaction: %v", err)
		}

		encodedTx, _ := xrpl.EncodeTransaction(payment, paymentFields.SignerAddress)
		if err != nil {
			log.Fatalf("could not construct payment transaction: %v", err)
		}

		txHash := xrpl.HashXRPMessage(encodedTx)

		logger.Infof("Payment hash: %v", hex.EncodeToString(txHash))

	case "sign_payment":
		// ---------- Parse arguments ---------- //
		providerPrivKey, err := getProviderPrivKey(args.Provider)
		if err != nil {
			log.Fatalf("could not get provider private key: %v", err)
		}

		paymentHash := args.Arg1

		txHash, err := hex.DecodeString(paymentHash)
		if err != nil {
			log.Fatalf("could not decode tx hash: %v", err)
		}

		keyIdBig, err := strconv.ParseUint(args.KeyId, 10, 32)
		if err != nil {
			log.Fatalf("could not parse key id: %v", err)
		}

		// ---------- Sign the message request ---------- //

		originalMessage := commonpayment.ITeePaymentsPaymentInstructionMessage{
			WalletId:           common.HexToHash(args.WalletId),
			SenderAddress:      "0x123",
			RecipientAddress:   "0x456",
			Amount:             big.NewInt(1000000000),
			PaymentReference:   [32]byte{},
			Nonce:              big.NewInt(0),
			SubNonce:           big.NewInt(0),
			MaxFee:             big.NewInt(0),
			MaxFeeTolerancePPM: big.NewInt(0),
			BatchEndTs:         big.NewInt(0),
		}
		originalMessageEncoded, err := abi.Arguments{commonpayment.MessageArguments[commonpayment.Pay]}.Pack(originalMessage)
		if err != nil {
			log.Fatalf("could not pack original message: %v", err)
		}

		instruction, err := utils.BuildMockInstruction(
			"XRP",
			"PAY",
			originalMessageEncoded,
			api.SignPaymentAdditionalFixedMessage{
				PaymentHash: paymentHash,
				KeyId:       big.NewInt(int64(keyIdBig)),
			},
			providerPrivKey,
			common.HexToAddress(args.TeeId),
			args.InstructionId,
			args.RewardEpochId,
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		// ---------- Send the transaction to the signing service ---------- //
		resp, err := utils.Post[api.InstructionResponse](config.Server.Host+"/instruction", instruction)
		if err != nil {
			log.Fatalf("could not sign payment transaction: %v", err)
		}

		logger.Info("Payment hash: %v", hex.EncodeToString(txHash))
		logger.Infof("sent request to SignPaymentTransaction, is ThresholdReached %v, Data %s, Token %v", resp.Finalized, resp.Data, resp.Token)

	case "get_payment_signature":
		nonceBytes, _ := utilsserver.GenerateRandomBytes(32)

		req := &api.InstructionResultRequest{
			InstructionId: args.InstructionId,
			Challenge:     hex.EncodeToString(nonceBytes),
		}

		resp, err := utils.Post[api.InstructionResultResponse](config.Server.Host+"/instruction/result", req)
		if err != nil {
			log.Fatalf("could not get the payment signature : %v", err)
		}

		var paymentSigResponse api.GetPaymentSignatureResponse
		err = json.Unmarshal(resp.Data, &paymentSigResponse)
		if err != nil {
			log.Fatalf("could not decode the payment signature : %v", err)
		}

		txnSignature := hex.EncodeToString(paymentSigResponse.TxnSignature)
		signingPubKey := hex.EncodeToString(paymentSigResponse.SigningPubKey)

		logger.Infof("sent request to GetPaymentSignature, is Account %v, TxnSignature %s, PublicKey %s, Token %v",
			paymentSigResponse.Account, txnSignature, signingPubKey, resp.Token)

	case "split_wallet":
		providerPrivKey, err := getProviderPrivKey(args.Provider)
		if err != nil {
			log.Fatalf("could not get provider private key: %v", err)
		}

		type NodeInfo struct {
			TeeId  string `json:"tee_id"`
			PubKey string `json:"pub_key"`
		}

		// Parse the JSON
		var nodeInfos []NodeInfo
		if err := json.Unmarshal([]byte(args.Arg1), &nodeInfos); err != nil {
			log.Fatalf("Failed to parse JSON: %v", err)
		}

		teeIds := make([]string, len(nodeInfos))
		pubKeys := make([]string, len(nodeInfos))
		for i, info := range nodeInfos {
			teeIds[i] = info.TeeId
			pubKeys[i] = info.PubKey
		}

		// TODO: Why am I using teeIds and then HexToAddress(pubKeys[id])?
		// Todo: Why are these not the same?

		// ---------- Split the wallet request ---------- //

		backupTeeMachines := make([]wallet.ITeeRegistryTeeMachineWithAttestationData, len(teeIds))
		for id := range teeIds {
			backupTeeMachines[id] = wallet.ITeeRegistryTeeMachineWithAttestationData{
				TeeId: common.HexToAddress(teeIds[id]),
				Url:   config.Server.Backups[id],
			}
		}
		// TODO: keyId and backupId parameters should probably be big.Int or uint32
		keyIdParsed, err := strconv.ParseUint(args.KeyId, 10, 32)
		if err != nil {
			log.Fatalf("could not parse key id: %v", err)
		}
		backupIdParsed, err := strconv.ParseUint(args.BackupId, 10, 32)
		if err != nil {
			log.Fatalf("could not parse backup id: %v", err)
		}
		originalMessage := wallet.ITeeWalletBackupManagerKeyMachineBackup{
			TeeMachine:        wallet.ITeeRegistryTeeMachineWithAttestationData{},
			WalletId:          common.HexToHash(args.WalletId),
			KeyId:             big.NewInt(int64(keyIdParsed)),
			BackupId:          big.NewInt(int64(backupIdParsed)),
			ShamirThreshold:   big.NewInt(int64(config.Server.BackupsThreshold)),
			BackupTeeMachines: backupTeeMachines,
		}
		originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[wallet.KeyMachineBackup]}.Pack(originalMessage)
		if err != nil {
			log.Fatalf("could not pack original message: %v", err)
		}
		additionalFixedMessage := api.SplitWalletAdditionalFixedMessage{
			PublicKeys: pubKeys,
		}

		instruction, err := utils.BuildMockInstruction("WALLET",
			"KEY_MACHINE_BACKUP",
			originalMessageEncoded,
			additionalFixedMessage,
			providerPrivKey,
			common.HexToAddress(args.TeeId),
			args.InstructionId,
			args.RewardEpochId,
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		resp, err := utils.Post[api.InstructionResponse](config.Server.Host+"/instruction", instruction)
		if err != nil {
			log.Fatalf("could not split wallet: %v", err)
		}

		logger.Infof("sent request to split wallet, is finalized %v", resp.Finalized)

	case "recover_wallet":
		providerPrivKey, err := getProviderPrivKey(args.Provider)
		if err != nil {
			log.Fatalf("could not get provider private key: %v", err)
		}

		numBackups := len(config.Server.Backups)

		shareIds := make([]string, numBackups)
		for i := range shareIds {
			shareIds[i] = strconv.Itoa(i + 1)
		}
		teeIds := make([]common.Address, len(shareIds))
		for i := range shareIds {
			teeIds[i] = common.HexToAddress(args.TeeIds[i])
		}

		backupTeeMachines := make([]wallet.ITeeRegistryTeeMachineWithAttestationData, len(shareIds))
		for i := range len(shareIds) {
			backupTeeMachines[i] = wallet.ITeeRegistryTeeMachineWithAttestationData{
				TeeId: common.HexToAddress(args.TeeIds[i]),
				Url:   config.Server.Backups[i],
			}
		}
		// TODO: keyId and backupId parameters should probably be big.Int or uint32
		keyIdParsed, err := strconv.ParseUint(args.KeyId, 10, 32)
		if err != nil {
			log.Fatalf("could not parse key id: %v", err)
		}
		backupIdParsed, err := strconv.ParseUint(args.BackupId, 10, 32)
		if err != nil {
			log.Fatalf("could not parse backup id: %v", err)
		}

		originalMessage := wallet.ITeeWalletBackupManagerKeyMachineRestore{
			TeeMachine:        wallet.ITeeRegistryTeeMachineWithAttestationData{},
			WalletId:          common.HexToHash(args.WalletId),
			KeyId:             big.NewInt(int64(keyIdParsed)),
			BackupId:          big.NewInt(int64(backupIdParsed)),
			OpType:            utilsserver.StringToOpHash("WALLET"),
			PublicKey:         common.Hex2Bytes(args.PubKey),
			BackupTeeMachines: backupTeeMachines,
		}
		originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[wallet.KeyMachineRestore]}.Pack(originalMessage)
		if err != nil {
			log.Fatalf("could not pack original message: %v", err)
		}
		additionalFixedMessage := api.RecoverWalletRequestAdditionalFixedMessage{
			TeeIds:    teeIds,
			ShareIds:  shareIds,
			Address:   args.Address,
			Threshold: int64(config.Server.BackupsThreshold),
		}

		instruction, err := utils.BuildMockInstruction("WALLET", "KEY_MACHINE_RESTORE", originalMessageEncoded,
			additionalFixedMessage,
			providerPrivKey,
			common.HexToAddress(args.TeeId),
			args.InstructionId,
			args.RewardEpochId,
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		resp, err := utils.Post[api.InstructionResponse](config.Server.Host+"/instruction", instruction)
		if err != nil {
			log.Fatalf("could not recover: %v", err)
		}

		logger.Infof("sent request to recover wallet, is finalized %v, attestation token %s", resp.Finalized, resp.Token)

	default:
		logger.Warn("call not recognized")
	}
}

func getProviderPrivKey(providerNum int) (*ecdsa.PrivateKey, error) {
	providersBytes, err := os.ReadFile("tests/test_providers.json")
	if err != nil {
		log.Fatalf("%v", err)
	}
	providers, err := utils.UnmarshalProviders(providersBytes)
	if err != nil {
		log.Fatalf("%v", err)
	}
	providerPrivKey := providers.PrivKeys[providerNum]

	return providerPrivKey, nil
}
