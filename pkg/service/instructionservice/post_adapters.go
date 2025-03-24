package instructionservice

import (
	"tee-node/pkg/requests"
	"tee-node/pkg/service/instructionservice/policyservice"
	"tee-node/pkg/service/instructionservice/signingservice"
	"tee-node/pkg/service/instructionservice/walletsservice"
	"tee-node/pkg/utils"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// * ----- REG OpType ----- * //

// TODO: Implement this service and APIs
func handleRegPostRequest(requestCounter *requests.RequestCounter) ([]byte, error) {
	switch utils.OpHashToString(requestCounter.Request.OPCommand) {
	case "AVAILABILITY_CHECK":
		return nil, status.Error(codes.Unimplemented, "REG AVAILABILITY_CHECK command not implemented yet")

	case "TO_PAUSE_FOR_UPGRADE":
		return nil, status.Error(codes.Unimplemented, "REG TO_PAUSE_FOR_UPGRADE command not implemented yet")

	case "REPLICATE_FROM":
		return nil, status.Error(codes.Unimplemented, "REG REPLICATE_FROM command not implemented yet")

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for WALLET OpType")
	}
}

func handlePolicyPostRequest(requestCounter *requests.RequestCounter) ([]byte, error) {
	switch utils.OpHashToString(requestCounter.Request.OPCommand) {
	case "UPDATE_POLICY":
		return []byte{}, policyservice.UpdatePolicy(requestCounter.Request)

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for WALLET OpType")
	}
}

// * ----- WALLET OpType ----- * //

func handleWalletPostRequest(requestCounter *requests.RequestCounter) ([]byte, error) {
	switch utils.OpHashToString(requestCounter.Request.OPCommand) {

	case "KEY_GENERATE":
		return []byte{}, walletsservice.NewWallet(requestCounter.Request)

	case "KEY_DELETE":
		return []byte{}, walletsservice.DeleteWallet(requestCounter.Request)

	case "KEY_MACHINE_BACKUP":
		return []byte{}, walletsservice.SplitWallet(requestCounter.Request, requestCounter.Signatures())

	case "KEY_MACHINE_RESTORE":
		return []byte{}, walletsservice.RecoverWallet(requestCounter.Request, requestCounter.Signatures())

	case "KEY_MACHINE_BACKUP_REMOVE":
		return walletsservice.KeyMachineBackupRemove(requestCounter.Request)

	case "KEY_CUSTODIAN_BACKUP":
		return walletsservice.KeyCustodianBackup(requestCounter.Request)

	case "KEY_CUSTODIAN_RESTORE":
		return walletsservice.KeyCustodianRestore(requestCounter.Request)

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for WALLET OpType")
	}

}

// * ----- XRP OpType ----- * //

// TODO: Implement this service and APIs
func handleXrpPostRequest(requestCounter *requests.RequestCounter) ([]byte, error) {

	switch utils.OpHashToString(requestCounter.Request.OPCommand) {
	case "PAY":
		return signingservice.SignPaymentTransaction(requestCounter.Request)

	case "REISSUE":
		return signingservice.XrpReissue(requestCounter.Request)

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for XRP OpType")
	}
}

func handleBtcPostRequest(requestCounter *requests.RequestCounter) ([]byte, error) {
	switch utils.OpHashToString(requestCounter.Request.OPCommand) {
	case "PAY":
		return nil, status.Error(codes.Unimplemented, "BTC PAY command not implemented yet")

	case "REISSUE":
		return nil, status.Error(codes.Unimplemented, "BTC REISSUE command not implemented yet")

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for BTC OpType")

	}
}

func handleFdcPostRequest(requestCounter *requests.RequestCounter) ([]byte, error) {
	switch utils.OpHashToString(requestCounter.Request.OPCommand) {
	case "PROVE":
		return nil, status.Error(codes.Unimplemented, "FDC PROVE command not implemented yet")

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for FDC OpType")
	}
}
