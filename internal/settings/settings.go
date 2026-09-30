package settings

import (
	"fmt"
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

	if err := configurePorts(); err != nil {
		panic(fmt.Sprintf("settings: %v", err))
	}
}

const EncodingVersion = "1.0.0"

// SignHost is the interface the sign/decrypt server binds to. It is fixed to
// loopback so the unauthenticated sign/decrypt API is reachable only from
// within the TEE instance, per the security model. It is intentionally not
// configurable.
const SignHost = "127.0.0.1"

// ConfigPort is the port the configuration server listens on. It is fixed
// rather than configurable: the Confidential Space launch policy enumerates the
// environment variables an operator may override, and this is not one of them,
// so a deployment could not change it in production regardless.
const ConfigPort = 5500

const (
	signPortEnvVar      = "SIGN_PORT"
	extensionPortEnvVar = "EXTENSION_PORT"
)

// signPort and extensionPort are unexported so that every mutation goes through
// configurePorts, which rejects a port the node cannot actually use. A caller
// outside this package can read them but not install one.
var (
	signPort      = 8888 // For signing action results received from extensions.
	extensionPort = 8889 // Extension's port that accepts actions.
)

// SignPort is the port the extension sign/decrypt server listens on.
func SignPort() int {
	return signPort
}

// ExtensionPort is the port the extension service listens on.
func ExtensionPort() int {
	return extensionPort
}

// configurePorts reads the configurable ports from the environment and installs
// them only if the whole resulting set is usable, so that exchanging two valid
// ports is accepted while any collision is not.
func configurePorts() error {
	sign, err := portFromEnv(signPortEnvVar, signPort)
	if err != nil {
		return err
	}
	extension, err := portFromEnv(extensionPortEnvVar, extensionPort)
	if err != nil {
		return err
	}

	return setPorts(sign, extension)
}

// portFromEnv reads a port from the named variable, returning fallback when it
// is unset. A value that is present but unusable is an error rather than being
// ignored, so a typo cannot silently leave the default in place.
func portFromEnv(envVar string, fallback int) (int, error) {
	raw := os.Getenv(envVar)
	if raw == "" {
		return fallback, nil
	}

	port, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a number", envVar, raw)
	}

	return port, nil
}

// setPorts installs the configurable ports after checking the node can serve on
// them. It is the only place they are assigned, so anything that reconfigures a
// port later - including a configuration-server endpoint - goes through this
// check rather than around it.
//
// A collision does not surface as a startup failure on its own: the config and
// sign servers are served from goroutines that only log a bind error, and a
// colliding extension port silently routes the node's own requests back at its
// config server. Both are rejected here, before anything binds.
func setPorts(sign, extension int) error {
	for _, p := range []struct {
		name  string
		value int
	}{
		{signPortEnvVar, sign},
		{extensionPortEnvVar, extension},
	} {
		if p.value <= 0 || p.value > 65535 {
			return fmt.Errorf("%s=%d is not a valid port", p.name, p.value)
		}
		if p.value == ConfigPort {
			return fmt.Errorf("%s=%d collides with the config port, which is fixed at %d", p.name, p.value, ConfigPort)
		}
	}

	if sign == extension {
		return fmt.Errorf("%s and %s are both %d", signPortEnvVar, extensionPortEnvVar, sign)
	}

	signPort, extensionPort = sign, extension

	return nil
}

// ownPorts maps every port the node listens on to a name for error messages.
func ownPorts() map[int]string {
	return map[int]string{
		ConfigPort:    "config port",
		signPort:      signPortEnvVar,
		extensionPort: extensionPortEnvVar,
	}
}

// Processor configuration
var QueuedActionsSleepTime = 2 * time.Second
var QueuedActionsPauseTime = 100 * time.Millisecond

const ProxyTimeout = 2 * time.Second

// extra fetch attempts after a timed-out poll; only timeouts are retried
const QueueFetchRetries = 2

const QueueFetchRetryDelay = 300 * time.Millisecond

// ActionProcessTimeout bounds the synchronous per-action processing time.
// When exceeded the action's context is cancelled so cancellation-aware
// processors short-circuit before committing state.
//
// Declared as var (not const) so tests can shrink it for fast cancellation
// assertions; production code only reads it.
var ActionProcessTimeout = 10 * time.Second

// ActionDrainTimeout bounds how long the queue worker waits for an in-flight
// processor to return after its context has been cancelled. Cooperative
// processors unwind well within this window. If a processor doesn't return
// in time the worker abandons it (the goroutine continues running but its
// result is discarded) and returns a state-unknown error so the queue keeps
// moving — accepting the leak as the lesser evil compared to wedging the
// queue forever.
//
// Declared as var (not const) so tests can shrink it; production code only
// reads it.
var ActionDrainTimeout = 5 * time.Second

const (
	MaxInstructionSize     = 100 * 1024       // 100 KB
	MaxActionSize          = 10 * 1024 * 1024 // 10 MB
	MaxFetchResponseSize   = 10 * 1024 * 1024 // 10 MB - limits the total size of a fetched action response
	MaxVariableMessageSize = 1024 * 1024      // 1 MB - limits the total size of all aggregated variable messages
	MaxVariableMessages    = 200              // Maximum number of per-signer variable messages (and signatures/timestamps) in an action. Bounds per-entry work like decrypt on restore.

	MaxWallets                = 200_000          // Maximum number of wallets that can be stored in memory. This is a safety limit to prevent OOM errors.
	MaxPermanentWalletsStatus = 1_000_000        // Maximum number of wallets that can be stored in permanent storage. This is a safety limit to prevent OOM errors.
	MaxAdminsPerWalletKey     = 50               // Maximum number of admins that can be associated with a wallet key.
	MaxCosignersPerWalletKey  = 50               // Maximum number of cosigners that can be associated with a wallet key.
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

	SetChainIDEndpoint = "/chain-id"
	ChainIDEnvVar      = "CHAIN_ID"

	SetGovernanceEndpoint     = "/governance"
	GovernanceSignersEnvVar   = "GOVERNANCE_SIGNERS"
	GovernanceThresholdEnvVar = "GOVERNANCE_THRESHOLD"
	// GovernanceSafeEnvVar and GovernanceTeeManagerEnvVar are
	// extra fields that configure Safe-backed governance
	GovernanceSafeEnvVar       = "GOVERNANCE_SAFE"
	GovernanceTeeManagerEnvVar = "GOVERNANCE_TEE_MANAGER"
)

var (
	// Modes:
	// - 0 production,
	// - 1 local (no attestation)
	Mode     = 1
	LogLevel = "FATAL"

	TestPlatform, _ = convert.StringToCommonHash("TEST_PLATFORM")
	TestCodeHash    = common.HexToHash("194844cf417dde867073e5ab7199fa4d21fd82b5dbe2bdea8b3d7fc18d10fdc2")

	DefaultExtensionID    = common.MaxHash
	DefaultGovernanceHash = common.MaxHash
)
