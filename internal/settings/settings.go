package settings

import (
	"time"

	"github.com/flare-foundation/tee-node/pkg/op"
)

// Modes:
// - 0 production,
// - 1 local (no attestation)
var Mode = 1

const MaxBIPS = 10000
const FtdcMinimumDataProvidersThreshold = float64(0.4)

const EncodingVersion = "1.0.0"

// Processor configuration
var QueuedActionsSleepTime = 100 * time.Millisecond

const ProxyConfigureServerPort = 5500
const ProxyTimeout = time.Second

const MaxInstructionSize = 100 * 1024 // 100 KB
const MaxActionSize = 1024 * 1024     // 1 MB

type MessageSizeConstraint struct {
	OriginalMessage           int
	AdditionalFixedMessage    int
	AdditionalVariableMessage int // todo: not yet used
}

// TODO: This is some base limit that can be overridden by specific opType and opCommand
var stdConstaints = MessageSizeConstraint{
	OriginalMessage:           50 * 1024,  // 50KB
	AdditionalFixedMessage:    100 * 1024, // 100KB
	AdditionalVariableMessage: 50 * 1024,  // 50KB
}

// Todo: We should define the size limits for each operation
var MaxRequestSize = map[op.Command]MessageSizeConstraint{
	op.TEEAttestation: stdConstaints,

	op.KeyGenerate: stdConstaints,
	op.KeyDelete:   stdConstaints,
	op.KeyDataProviderRestore: {
		OriginalMessage:           50 * 1024,   // 50KB
		AdditionalFixedMessage:    100 * 1024,  // 100KB
		AdditionalVariableMessage: 1024 * 1024, // 50KB
	},

	op.Pay:     stdConstaints,
	op.Reissue: stdConstaints,

	op.Prove: stdConstaints,
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
