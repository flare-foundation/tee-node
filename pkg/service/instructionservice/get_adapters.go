package instructionservice

import (
	"encoding/json"
	"tee-node/pkg/requests"
	"tee-node/pkg/service/instructionservice/signinginstruction"
	"tee-node/pkg/utils"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// * ----- REG OpType ----- * //

// TODO: Implement this service and APIs
func handleRegGetRequest(requestCounter *requests.RequestCounter) ([]byte, error) {
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

// * ----- WALLET OpType ----- * //

func handleWalletGetRequest(requestCounter *requests.RequestCounter) ([]byte, error) {
	switch utils.OpHashToString(requestCounter.Request.OPCommand) {

	case "KEY_GENERATE":

		// TODO:
		return nil, nil

	case "KEY_DELETE":

		// TODO:
		return nil, nil

	case "KEY_MACHINE_BACKUP":

		// TODO:
		return nil, nil

	case "KEY_MACHINE_RESTORE":

		// TODO:
		return nil, nil

	case "KEY_MACHINE_BACKUP_REMOVE":

		return nil, status.Error(codes.Unimplemented, "WALLET KEY_MACHINE_BACKUP_REMOVE command not implemented yet")

	case "KEY_CUSTODIAN_BACKUP":

		return nil, status.Error(codes.Unimplemented, "WALLET KEY_CUSTODIAN_BACKUP command not implemented yet")

	case "KEY_CUSTODIAN_RESTORE":

		return nil, status.Error(codes.Unimplemented, "WALLET KEY_CUSTODIAN_RESTORE command not implemented yet")

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for WALLET OpType")
	}
}

// * ----- XRP OpType ----- * //

func handleXrpGetRequest(requestCounter *requests.RequestCounter) ([]byte, error) {

	switch utils.OpHashToString(requestCounter.Request.OPCommand) {
	case "PAY":

		response, err := signinginstruction.GetPaymentSignature(requestCounter.Request, requestCounter.Result)
		if err != nil {
			return nil, err
		}

		encodedResponse, err := json.Marshal(response)
		if err != nil {
			return nil, err
		}

		return encodedResponse, nil

	case "REISSUE":
		return nil, status.Error(codes.Unimplemented, "XRP RESISSUE command not implemented yet")

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for XRP OpType")
	}

}

func handleBtcGetRequest(requestCounter *requests.RequestCounter) ([]byte, error) {
	switch utils.OpHashToString(requestCounter.Request.OPCommand) {
	case "PAY":
		return nil, status.Error(codes.Unimplemented, "BTC PAY command not implemented yet")

	case "REISSUE":
		return nil, status.Error(codes.Unimplemented, "BTC REISSUE command not implemented yet")

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for BTC OpType")

	}
}

func handleFdcGetRequest(requestCounter *requests.RequestCounter) ([]byte, error) {
	switch utils.OpHashToString(requestCounter.Request.OPCommand) {
	case "PROVE":
		return nil, status.Error(codes.Unimplemented, "FDC PROVE command not implemented yet")

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for FDC OpType")
	}
}
