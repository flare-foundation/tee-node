package node_test

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/types"
)

// serveOnPort runs h on a loopback port until the test ends and returns the port,
// because NewExtensionState derives the URL from a port rather than taking one.
func serveOnPort(t *testing.T, h http.Handler) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	return port
}

func TestZeroStateIsEmpty(t *testing.T) {
	state, err := node.ZeroState{}.State()
	require.NoError(t, err)
	require.Empty(t, state.State)
	require.Equal(t, common.Hash{}, state.StateVersion)
	require.Empty(t, state.SystemState)
	require.Equal(t, common.Hash{}, state.SystemStateVersion)
}

func TestExtensionStateFetches(t *testing.T) {
	version := common.HexToHash("0xabc")
	port := serveOnPort(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/state", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		_, _ = fmt.Fprintf(w, `{"state":"0xdeadbeef","stateVersion":%q}`, version)
	}))

	state, err := node.NewExtensionState(port).State()
	require.NoError(t, err)
	require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, []byte(state.State))
	require.Equal(t, version, state.StateVersion)
}

// The extension must not be able to contribute system state: it is signed into
// the attestation alongside the node's own claims.
func TestExtensionStateIgnoresSystemHalf(t *testing.T) {
	port := serveOnPort(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"state":"0x01","stateVersion":%q,`+
			`"systemState":"0xffff","systemStateVersion":%q}`,
			common.HexToHash("0x02"), common.HexToHash("0x03"))
	}))

	state, err := node.NewExtensionState(port).State()
	require.NoError(t, err)
	require.Equal(t, []byte{0x01}, []byte(state.State))
	require.Empty(t, state.SystemState, "extension-supplied system state must be dropped")
	require.Equal(t, common.Hash{}, state.SystemStateVersion)
}

// A /state route that is down, broken, or hung must not fail the caller. Each
// case reports StateUnavailableVersion so the attestation says "state unknown"
// rather than "no state".
func TestExtensionStateReportsUnavailable(t *testing.T) {
	requireUnavailable := func(t *testing.T, port int) {
		t.Helper()

		state, err := node.NewExtensionState(port).State()
		require.NoError(t, err, "a failed fetch must not fail the caller")
		require.Equal(t, types.StateUnavailableVersion, state.StateVersion)
		require.Empty(t, state.State)
		require.Empty(t, state.SystemState)
		require.Equal(t, common.Hash{}, state.SystemStateVersion)
	}

	t.Run("non-200", func(t *testing.T) {
		requireUnavailable(t, serveOnPort(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "no state here", http.StatusServiceUnavailable)
		})))
	})

	t.Run("malformed json", func(t *testing.T) {
		requireUnavailable(t, serveOnPort(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprint(w, `{"state":`)
		})))
	})

	t.Run("unreachable extension", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		_, portStr, err := net.SplitHostPort(ln.Addr().String())
		require.NoError(t, err)
		require.NoError(t, ln.Close()) // nothing is listening now

		port, err := strconv.Atoi(portStr)
		require.NoError(t, err)

		requireUnavailable(t, port)
	})

	// The client timeout must match the one used for the extension's /action
	// route, so a hung extension cannot outlive the per-action budget.
	t.Run("hung extension times out at ProxyTimeout", func(t *testing.T) {
		port := serveOnPort(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))

		start := time.Now()
		requireUnavailable(t, port)

		require.Less(t, time.Since(start), settings.ProxyTimeout*3,
			"fetch must not outlive the extension client timeout")
	})
}

// The unavailable sentinel must not collide with the state of a node that has
// no extension, or a consumer cannot tell the two apart.
func TestUnavailableIsDistinctFromZeroState(t *testing.T) {
	zero, err := node.ZeroState{}.State()
	require.NoError(t, err)
	require.NotEqual(t, types.StateUnavailableVersion, zero.StateVersion)
}

// An oversized body is truncated at MaxFetchResponseSize rather than read
// unbounded, matching how fetched action responses are bounded.
func TestExtensionStateBoundsResponseSize(t *testing.T) {
	port := serveOnPort(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"state":"0x`))
		chunk := bytes.Repeat([]byte("ab"), 64*1024)
		for written := 0; written < settings.MaxFetchResponseSize+len(chunk); written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))

	// Truncation yields invalid JSON, reported as unavailable rather than parsed
	// from an unbounded read.
	state, err := node.NewExtensionState(port).State()
	require.NoError(t, err)
	require.Equal(t, types.StateUnavailableVersion, state.StateVersion)
}
