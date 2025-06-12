package settings

import (
	"time"
)

// Modes:
// - 0 production,
// - 1 local (no attestation)
var Mode = 1

const ProxyUrl = "http://localhost:8545"

var InitialPolicyHash = "6c5d823aa3ecf8e2a00f7bad8b03d6e4557de9ac7be7c5d8408047f5a31f4fd1"

const ProxyTimeout = time.Second

// var InitialPolicyBytesHex = "" // TODO: Add the initial policy bytes here as a hex string

// Processor configuration
var QueuedActionsSleepTime = 100 * time.Millisecond

// Hardcoded configuration for operations and subcommands
var InstructionOperations = map[string]map[string]bool{
	"REG": {
		"AVAILABILITY_CHECK":   true,
		"TO_PAUSE_FOR_UPGRADE": true,
		"REPLICATE_FROM":       true,
	},
	"WALLET": {
		"KEY_GENERATE":              true,
		"KEY_DELETE":                true,
		"KEY_DATA_PROVIDER_RESTORE": true,
	},
	"XRP": {
		"PAY":     true,
		"REISSUE": true,
	},
	// "BTC": {
	// 	"PAY":     true,
	// 	"REISSUE": true,
	// },
	"FDC": {
		"PROVE": true,
	},
}

const MaxInstructionSize = 100 * 1024 // 100 KB
const MaxActionSize = 1024 * 1024     // 1 MB

type MessageSizeConstraint struct {
	MaxOriginalMessageSize           int
	MaxAdditionalFixedMessageSize    int
	MaxAdditionalVariableMessageSize int // todo: not yet used
}

// TODO: This is some base limit that can be overridden by specific opType and opCommand
var standardSizeConstraint = MessageSizeConstraint{
	MaxOriginalMessageSize:           50 * 1024,  // 50KB
	MaxAdditionalFixedMessageSize:    100 * 1024, // 100KB
	MaxAdditionalVariableMessageSize: 50 * 1024,  // 50KB
}

// Todo: We should define the size limits for each operation
var MaxRequestSize = map[string]map[string]MessageSizeConstraint{
	"REG": {
		"AVAILABILITY_CHECK":   standardSizeConstraint,
		"TO_PAUSE_FOR_UPGRADE": standardSizeConstraint,
		"REPLICATE_FROM":       standardSizeConstraint,
	},
	"WALLET": {
		"KEY_GENERATE": standardSizeConstraint,
		"KEY_DELETE":   standardSizeConstraint,
		"KEY_DATA_PROVIDER_RESTORE": MessageSizeConstraint{
			MaxOriginalMessageSize:           50 * 1024,   // 50KB
			MaxAdditionalFixedMessageSize:    100 * 1024,  // 100KB
			MaxAdditionalVariableMessageSize: 1024 * 1024, // 50KB
		},
	},
	"XRP": {
		"PAY":     standardSizeConstraint,
		"REISSUE": standardSizeConstraint,
	},
	// "BTC": {
	// 	"PAY":     standardSizeConstraint,
	// 	"REISSUE": standardSizeConstraint,
	// },
	"FDC": {
		"PROVE": standardSizeConstraint,
	},
}

var NormalizationConstant = 1000

var DataProvidersBackupThreshold = uint64(666)

func WeightsNormalization(weights []uint16) []uint16 {
	sum := uint16(0)
	for _, weight := range weights {
		sum += weight
	}

	normalizedWeighs := make([]uint16, len(weights))

	for i, weight := range weights {
		normalizedWeighs[i] = uint16((int(weight) * NormalizationConstant) / int(sum))
	}

	return normalizedWeighs
}

// var GovernanceSigners = []common.Address{
// 	common.HexToAddress("0x0000000000000000000000000000000000000000"),
// }

// const GovernanceThreshold uint8 = 1
