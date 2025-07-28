package settings

import (
	"time"
)

// Modes:
// - 0 production,
// - 1 local (no attestation)
var Mode = 1

const ProxyUrl = "http://localhost:8545"

const BIPSConstant = 10000
const FtdcMinimumDataProvidersThreshold = float64(0.4)

const EncodingVersion = "1.0.0"

// Processor configuration
var QueuedActionsSleepTime = 100 * time.Millisecond

const ProxyTimeout = time.Second

// Hardcoded configuration for operations and subcommands
var InstructionOperations = map[string]map[string]bool{
	"REG": {
		"TEE_ATTESTATION": true,
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
	"FTDC": {
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
		"TEE_ATTESTATION": standardSizeConstraint,
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
	"FTDC": {
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

const GoogleCertLoc = "assets/google_confidential_space_root.crt"
