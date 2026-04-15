package settings

import (
	"os"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/convert"
)

func init() {
	if m, err := strconv.Atoi(os.Getenv("MODE")); err == nil {
		Mode = m
	}

	if logLevelEnv := os.Getenv("LOG_LEVEL"); len(logLevelEnv) != 0 {
		LogLevel = logLevelEnv
	}

	if port, err := strconv.Atoi(os.Getenv("CONFIG_PORT")); err == nil && port > 0 && port <= 65535 {
		ConfigPort = port
	}

	if port, err := strconv.Atoi(os.Getenv("SIGN_PORT")); err == nil && port > 0 && port <= 65535 {
		SignPort = port
	}

	if port, err := strconv.Atoi(os.Getenv("EXTENSION_PORT")); err == nil && port > 0 && port <= 65535 {
		ExtensionPort = port
	}
}

const EncodingVersion = "1.0.0"

// Processor configuration
var QueuedActionsSleepTime = 100 * time.Millisecond

const ProxyTimeout = 2 * time.Second

const (
	MaxInstructionSize     = 100 * 1024       // 100 KB
	MaxActionSize          = 10 * 1024 * 1024 // 10 MB
	MaxFetchResponseSize   = 10 * 1024 * 1024 // 10 MB - limits the total size of a fetched action response
	MaxVariableMessageSize = 1024 * 1024      // 1 MB - limits the total size of all aggregated variable messages

	MaxWallets                = 200_000          // Maximum number of wallets that can be stored in memory. This is a safety limit to prevent OOM errors.
	MaxPermanentWalletsStatus = 1_000_000        // Maximum number of wallets that can be stored in permanent storage. This is a safety limit to prevent OOM errors.
	MaxSignGoroutines         = 3000             // Maximum number of concurrent XRP sign schedule goroutines. Prevents OOM from accumulated sleeping goroutines.
	MaxFeeEntries             = 50               // Maximum number of fee schedule entries per XRP sign instruction.
	MaxFeeScheduleTime        = 10 * time.Minute // Maximum delay allowed in a fee schedule entry.
)

const (
	SetProxyURLEndpoint = "/proxy"
	ProxyURLEnvVar      = "PROXY_URL"

	SetInitialOwnerEndpoint = "/initial-owner"
	InitialOwnerEnvVar      = "INITIAL_OWNER"

	SetExtensionIDEndpoint = "/extension-id"
	ExtensionIDEnvVar      = "EXTENSION_ID"
)

var (
	// Modes:
	// - 0 production,
	// - 1 local (no attestation)
	Mode     = 1
	LogLevel = "FATAL"

	ConfigPort    = 5500 // For node configuration.
	SignPort      = 8888 // For signing action results received from extensions.
	ExtensionPort = 8889 // Extension's port that accepts actions.

	TestPlatform, _ = convert.StringToCommonHash("TEST_PLATFORM")
	TestCodeHash    = common.HexToHash("194844cf417dde867073e5ab7199fa4d21fd82b5dbe2bdea8b3d7fc18d10fdc2")

	DefaultExtensionID = common.MaxHash
)
