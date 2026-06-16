package policyutils

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	commonpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	csigning "github.com/flare-foundation/go-flare-common/pkg/signing"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/machinepath"
	"github.com/stretchr/testify/require"

	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/policy"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
)

// Test constants
const numVoters = 100

// policyTestSetup holds common test setup data for policy tests
type policyTestSetup struct {
	pStorage      *policy.Storage
	node          *node.Node
	processor     Processor
	voters        []common.Address
	privKeys      []*ecdsa.PrivateKey
	pubKeysMap    map[common.Address]*ecdsa.PublicKey
	pubKeys       []types.PublicKey
	initialPolicy *commonpolicy.SigningPolicy
	randSeed      int64
}

// setupPolicyTest creates a standard test environment for policy tests
func setupPolicyTest(t *testing.T) *policyTestSetup {
	t.Helper()

	pStorage := policy.InitializeStorage()
	teeNode, err := node.Initialize(node.ZeroState{})
	require.NoError(t, err)
	processor := NewProcessor(teeNode, pStorage)

	epochID := uint32(1)
	n, err := rand.Int(rand.Reader, big.NewInt(100000000))
	require.NoError(t, err)
	randSeed := n.Int64()

	voters, privKeys, pubKeysMap := testutils.GenerateRandomKeys(t, numVoters)
	initialPolicy := testutils.GenerateRandomPolicyData(t, epochID, voters, randSeed)

	pubKeys := make([]types.PublicKey, len(voters))
	for i, voter := range voters {
		pubKeys[i] = types.PubKeyToStruct(pubKeysMap[voter])
	}

	return &policyTestSetup{
		pStorage:      pStorage,
		node:          teeNode,
		processor:     processor,
		voters:        voters,
		privKeys:      privKeys,
		pubKeysMap:    pubKeysMap,
		pubKeys:       pubKeys,
		initialPolicy: initialPolicy,
		randSeed:      randSeed,
	}
}

// setupPolicyTestWithInitializedPolicy creates a test environment with policy already initialized
func setupPolicyTestWithInitializedPolicy(t *testing.T) *policyTestSetup {
	t.Helper()

	setup := setupPolicyTest(t)

	err := setup.pStorage.SetInitialPolicy(setup.initialPolicy, setup.pubKeysMap)
	require.NoError(t, err)

	return setup
}

// generateNextPolicy generates a policy for the next epoch
func (s *policyTestSetup) generateNextPolicy(t *testing.T, offset uint32) (*commonpolicy.SigningPolicy, []types.PublicKey) {
	t.Helper()

	nextEpochID := s.initialPolicy.RewardEpochID + offset
	nextPolicy := testutils.GenerateRandomPolicyData(t, nextEpochID, s.voters, s.randSeed+int64(offset))

	pubKeys := make([]types.PublicKey, len(s.voters))
	for i, voter := range s.voters {
		pubKeys[i] = types.PubKeyToStruct(s.pubKeysMap[voter])
	}

	return nextPolicy, pubKeys
}

// executeInitializePolicy executes InitializePolicy with the given request
func (s *policyTestSetup) executeInitializePolicy(t *testing.T, req *types.InitializePolicyRequest) ([]byte, error) {
	t.Helper()

	message, err := json.Marshal(req)
	require.NoError(t, err)

	return s.processor.InitializePolicy(context.Background(), &types.DirectInstruction{Message: message})
}

// executeUpdatePolicy executes UpdatePolicy with the given request
func (s *policyTestSetup) executeUpdatePolicy(t *testing.T, req *types.UpdatePolicyRequest) ([]byte, error) {
	t.Helper()

	message, err := json.Marshal(req)
	require.NoError(t, err)

	return s.processor.UpdatePolicy(context.Background(), &types.DirectInstruction{Message: message})
}

func TestInitializePolicyBasicFlow(t *testing.T) {
	setup := setupPolicyTest(t)

	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: setup.initialPolicy.RawBytes(),
		PublicKeys:         setup.pubKeys,
	}
	_, err := setup.executeInitializePolicy(t, req)
	require.NoError(t, err)

	activePolicy, err := setup.pStorage.ActiveSigningPolicy()
	require.NoError(t, err)
	require.Equal(t, setup.initialPolicy.RewardEpochID, activePolicy.RewardEpochID)
	require.Equal(t, setup.initialPolicy.Hash(), activePolicy.Hash())
}

func TestInitializePolicyAlreadyInitialized(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	// Try to initialize again with a different policy
	newEpochID := uint32(2)
	newPolicy := testutils.GenerateRandomPolicyData(t, newEpochID, setup.voters, int64(54321))

	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: newPolicy.RawBytes(),
		PublicKeys:         setup.pubKeys,
	}
	_, err := setup.executeInitializePolicy(t, req)
	require.Error(t, err)
	require.Equal(t, "policy already initialized", err.Error())
}

func TestInitializePolicyInvalidJSON(t *testing.T) {
	setup := setupPolicyTest(t)

	invalidMessage := []byte(`{"invalid": "json"`)
	_, err := setup.processor.InitializePolicy(context.Background(), &types.DirectInstruction{Message: invalidMessage})
	require.Error(t, err)
}

func TestInitializePolicyInvalidPolicyBytes(t *testing.T) {
	setup := setupPolicyTest(t)

	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: []byte{0x01, 0x02, 0x03}, // Invalid policy bytes
		PublicKeys:         setup.pubKeys,
	}

	_, err := setup.executeInitializePolicy(t, req)
	require.Error(t, err)
}

func TestInitializePolicyEmptyPolicyBytes(t *testing.T) {
	setup := setupPolicyTest(t)

	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: []byte{},
		PublicKeys:         setup.pubKeys,
	}

	_, err := setup.executeInitializePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "message too short for decoding signing policy")
}

func TestInitializePolicyMismatchedPublicKeysCount(t *testing.T) {
	setup := setupPolicyTest(t)

	// Provide fewer public keys than voters
	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: setup.initialPolicy.RawBytes(),
		PublicKeys:         setup.pubKeys[:numVoters/2],
	}
	_, err := setup.executeInitializePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "number of public keys and the number of voters do not match")
}

func TestInitializePolicyEmptyPublicKeys(t *testing.T) {
	setup := setupPolicyTest(t)

	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: setup.initialPolicy.RawBytes(),
		PublicKeys:         []types.PublicKey{},
	}
	_, err := setup.executeInitializePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "number of public keys and the number of voters do not match")
}

func TestInitializePolicyWrongPublicKeyAddress(t *testing.T) {
	for range 10 {
		setup := setupPolicyTest(t)

		// Replace first public key with a different one
		wrongPubKeys := make([]types.PublicKey, len(setup.pubKeys))

		copy(wrongPubKeys, setup.pubKeys)

		wrongPubKeys[0] = types.PublicKey{
			X: [32]byte{0, 1, 2, 3}, // not a valid public key
			Y: [32]byte{3, 4, 5, 6},
		}

		req := &types.InitializePolicyRequest{
			InitialPolicyBytes: setup.initialPolicy.RawBytes(),
			PublicKeys:         wrongPubKeys,
		}
		_, err := setup.executeInitializePolicy(t, req)
		require.Contains(t, err.Error(), "invalid public key bytes")
		require.Error(t, err)

		// Generate a new key that doesn't match the first voter, but is a valid public key
		newPrivKey, err := crypto.GenerateKey()
		require.NoError(t, err)

		wrongPubKeys[0] = types.PublicKey{
			X: common.BigToHash(newPrivKey.X),
			Y: common.BigToHash(newPrivKey.Y),
		}

		req2 := &types.InitializePolicyRequest{
			InitialPolicyBytes: setup.initialPolicy.RawBytes(),
			PublicKeys:         wrongPubKeys,
		}
		_, err = setup.executeInitializePolicy(t, req2)
		require.Contains(t, err.Error(), "public key and address do not match")
		require.Error(t, err)
	}
}

func TestInitializePolicyRollbackOnError(t *testing.T) {
	setup := setupPolicyTest(t)

	// Try to initialize with invalid public keys
	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: setup.initialPolicy.RawBytes(),
		PublicKeys:         setup.pubKeys[:numVoters/2],
	}
	_, err := setup.executeInitializePolicy(t, req)
	require.Error(t, err)

	// Verify storage was rolled back (DestroyState was called)
	_, err = setup.pStorage.ActiveSigningPolicy()
	require.Error(t, err)
	require.Equal(t, "signing policy not initialized", err.Error())
}

// TestInitializePolicyPreservesLivePolicyOnError verifies that a failed
// InitializePolicy on an already-initialized node never destroys the live
// signing policy. Pre-mutation errors (malformed JSON, undecodable policy bytes,
// mismatched public keys) must leave the active policy untouched, since
// InitializePolicy carries no signature and is reachable as a direct action.
func TestInitializePolicyPreservesLivePolicyOnError(t *testing.T) {
	badRequests := map[string][]byte{
		"malformed JSON":      []byte(`{"invalid": "json"`),
		"undecodable policy":  mustMarshal(t, &types.InitializePolicyRequest{InitialPolicyBytes: []byte{0x01, 0x02, 0x03}}),
		"mismatched pubkeys":  nil, // filled in per-iteration below to use the setup's policy bytes
		"already initialized": nil,
	}

	for name := range badRequests {
		t.Run(name, func(t *testing.T) {
			setup := setupPolicyTestWithInitializedPolicy(t)
			wantEpoch := setup.initialPolicy.RewardEpochID
			wantHash := setup.initialPolicy.Hash()

			var message []byte
			switch name {
			case "mismatched pubkeys":
				message = mustMarshal(t, &types.InitializePolicyRequest{
					InitialPolicyBytes: setup.initialPolicy.RawBytes(),
					PublicKeys:         setup.pubKeys[:numVoters/2],
				})
			case "already initialized":
				message = mustMarshal(t, &types.InitializePolicyRequest{
					InitialPolicyBytes: setup.initialPolicy.RawBytes(),
					PublicKeys:         setup.pubKeys,
				})
			default:
				message = badRequests[name]
			}

			_, err := setup.processor.InitializePolicy(context.Background(), &types.DirectInstruction{Message: message})
			require.Error(t, err)

			// The live policy must still be present and unchanged.
			active, err := setup.pStorage.ActiveSigningPolicy()
			require.NoError(t, err, "live policy must not be destroyed by a failed re-initialization")
			require.Equal(t, wantEpoch, active.RewardEpochID)
			require.Equal(t, wantHash, active.Hash())
		})
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestUpdatePolicyBasicFlow(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	// Generate next policy
	nextPolicy, pubKeys := setup.generateNextPolicy(t, 1)

	req := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, nextPolicy.RawBytes(), setup.privKeys),
		PublicKeys: pubKeys,
	}
	_, err := setup.executeUpdatePolicy(t, req)
	require.NoError(t, err)

	// Verify the policy was updated
	activePolicy, err := setup.pStorage.ActiveSigningPolicy()
	require.NoError(t, err)
	require.Equal(t, nextPolicy.RewardEpochID, activePolicy.RewardEpochID)
	require.Equal(t, nextPolicy.Hash(), activePolicy.Hash())
}

func TestUpdatePolicyNotInitialized(t *testing.T) {
	setup := setupPolicyTest(t)

	// Try to update without initializing first
	nextPolicy, pubKeys := setup.generateNextPolicy(t, 1)
	req := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, nextPolicy.RawBytes(), setup.privKeys),
		PublicKeys: pubKeys,
	}

	_, err := setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "signing policy not initialized")
}

func TestUpdatePolicyInvalidJSON(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	invalidMessage := []byte(`{"invalid": "json"`)
	_, err := setup.processor.UpdatePolicy(context.Background(), &types.DirectInstruction{Message: invalidMessage})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected end of JSON input")
}

func TestUpdatePolicyInvalidPolicyBytes(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	req := &types.UpdatePolicyRequest{
		NewPolicy: types.MultiSignedPolicy{
			PolicyBytes: []byte{0x01, 0x02, 0x03},
			Signatures:  [][]byte{},
		},
		PublicKeys: setup.pubKeys,
	}

	_, err := setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "message too short for decoding signing policy")
}

func TestUpdatePolicyEmptyPolicyBytes(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	req := &types.UpdatePolicyRequest{
		NewPolicy: types.MultiSignedPolicy{
			PolicyBytes: []byte{},
			Signatures:  [][]byte{},
		},
		PublicKeys: setup.pubKeys,
	}

	_, err := setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "message too short for decoding signing policy")
}

func TestUpdatePolicyWrongEpochID(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	// Generate policy with wrong epoch (skip one)
	wrongEpochID := setup.initialPolicy.RewardEpochID + 2
	wrongPolicy := testutils.GenerateRandomPolicyData(t, wrongEpochID, setup.voters, setup.randSeed+2)

	req := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, wrongPolicy.RawBytes(), setup.privKeys),
		PublicKeys: setup.pubKeys,
	}
	_, err := setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "policy is not active")
}

func TestUpdatePolicySameEpochID(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	// Try to update with same epoch ID
	sameEpochPolicy := testutils.GenerateRandomPolicyData(t, setup.initialPolicy.RewardEpochID, setup.voters, setup.randSeed+100)

	req := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, sameEpochPolicy.RawBytes(), setup.privKeys),
		PublicKeys: setup.pubKeys,
	}
	_, err := setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "policy is not active")
}

func TestUpdatePolicyInsufficientSignatures(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	nextPolicy, pubKeys := setup.generateNextPolicy(t, 1)

	// Use fewer signers than needed (half of what's needed)
	insufficientSigners := setup.privKeys[:(len(setup.privKeys) / 10)]

	req := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, nextPolicy.RawBytes(), insufficientSigners),
		PublicKeys: pubKeys,
	}
	_, err := setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "threshold for updating policy not reached")
}

func TestUpdatePolicyNoSignatures(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	nextPolicy, pubKeys := setup.generateNextPolicy(t, 1)

	req := &types.UpdatePolicyRequest{
		NewPolicy: types.MultiSignedPolicy{
			PolicyBytes: nextPolicy.RawBytes(),
			Signatures:  [][]byte{},
		},
		PublicKeys: pubKeys,
	}

	_, err := setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "threshold for updating policy not reached")
}

func TestUpdatePolicyInvalidSignatureLength(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	nextPolicy, pubKeys := setup.generateNextPolicy(t, 1)

	// Build request with valid signatures
	req := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, nextPolicy.RawBytes(), setup.privKeys),
		PublicKeys: pubKeys,
	}

	// Corrupt one signature with invalid length
	req.NewPolicy.Signatures[0] = []byte{0x01, 0x02, 0x03}

	_, err := setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid signature length")
}

func TestUpdatePolicyInvalidSignature(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	nextPolicy, pubKeys := setup.generateNextPolicy(t, 1)

	// Build request with valid signatures from all voters
	req := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, nextPolicy.RawBytes(), setup.privKeys),
		PublicKeys: pubKeys,
	}

	// Create a signature from a non-voter (not in the voter set)
	// This ensures the signature is valid (recovery will work) but the
	// recovered address won't be in the voter list
	nonVoterPrivKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	// Sign the policy with the non-voter's key
	nonVoterSignedPolicy := testutils.BuildMultiSignedPolicy(t, nextPolicy.RawBytes(), []*ecdsa.PrivateKey{nonVoterPrivKey})
	nonVoterSig := nonVoterSignedPolicy.Signatures[0]

	// Replace one valid signature with the non-voter's signature
	req.NewPolicy.Signatures[0] = nonVoterSig

	_, err = setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a voter")
}

func TestUpdatePolicyMismatchedPublicKeysCount(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	nextPolicy, _ := setup.generateNextPolicy(t, 1)

	// Provide fewer public keys than voters
	req := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, nextPolicy.RawBytes(), setup.privKeys),
		PublicKeys: setup.pubKeys[:numVoters/2],
	}
	_, err := setup.executeUpdatePolicy(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "number of public keys and the number of voters do not match")
}

func TestUpdatePolicyMultipleUpdates(t *testing.T) {
	setup := setupPolicyTestWithInitializedPolicy(t)

	// First update
	nextPolicy1, pubKeys1 := setup.generateNextPolicy(t, 1)
	req1 := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, nextPolicy1.RawBytes(), setup.privKeys),
		PublicKeys: pubKeys1,
	}
	_, err := setup.executeUpdatePolicy(t, req1)
	require.NoError(t, err)

	// Second update
	nextPolicy2, pubKeys2 := setup.generateNextPolicy(t, 2)
	req2 := &types.UpdatePolicyRequest{
		NewPolicy:  testutils.BuildMultiSignedPolicy(t, nextPolicy2.RawBytes(), setup.privKeys),
		PublicKeys: pubKeys2,
	}
	_, err = setup.executeUpdatePolicy(t, req2)
	require.NoError(t, err)

	// Verify final policy
	activePolicy, err := setup.pStorage.ActiveSigningPolicy()
	require.NoError(t, err)
	require.Equal(t, nextPolicy2.RewardEpochID, activePolicy.RewardEpochID)
}

// testChainID is the chain ID used by every governance-signed test in
// this file. It is fixed so signature checks are deterministic.
const testChainID uint64 = 31337

// executeSetMachinePathList runs SetMachinePathList with the given request.
func (s *policyTestSetup) executeSetMachinePathList(t *testing.T, req *types.SetMachinePathListRequest) ([]byte, error) {
	t.Helper()

	message, err := json.Marshal(req)
	require.NoError(t, err)

	return s.processor.SetMachinePathList(context.Background(), &types.DirectInstruction{Message: message})
}

// configureGovernance installs a 2-of-3 governance signer set on the node
// plus the test chain ID, and returns the private keys so tests can
// sign.
func configureGovernance(t *testing.T, n *node.Node) []*ecdsa.PrivateKey {
	t.Helper()

	const (
		count     = 3
		threshold = uint64(2)
	)
	privKeys := make([]*ecdsa.PrivateKey, count)
	addrs := make([]common.Address, count)
	for i := range count {
		pk, err := crypto.GenerateKey()
		require.NoError(t, err)
		privKeys[i] = pk
		addrs[i] = crypto.PubkeyToAddress(pk.PublicKey)
	}
	require.NoError(t, n.SetGovernance(addrs, threshold))
	require.NoError(t, n.SetChainID(testChainID))
	return privKeys
}

// singlePathList wraps a (source, destination) pair into the single-path
// list used by every test in this file.
func singlePathList(source, destination []common.Address) []machinepath.IMachinePathManagerMachinePath {
	return []machinepath.IMachinePathManagerMachinePath{{SourceTeeIds: source, DestinationTeeIds: destination}}
}

// signMachinePathList computes the canonical machine-path-list message
// hash for a single (source, destination) path and signs it with each
// provided key.
func signMachinePathList(t *testing.T, n *node.Node, source, destination []common.Address, nonce uint64, keys []*ecdsa.PrivateKey) [][]byte {
	t.Helper()

	dataHash, err := types.MachinePathListDataHash(n.Info().ExtensionID, nonce, singlePathList(source, destination))
	require.NoError(t, err)
	hash, err := csigning.NewPayload(csigning.TEEMachinePathList, testChainID, dataHash).Hash()
	require.NoError(t, err)

	sigs := make([][]byte, len(keys))
	for i, key := range keys {
		sig, err := utils.Sign(hash[:], key)
		require.NoError(t, err)
		sigs[i] = sig
	}
	return sigs
}

func TestSetMachinePathListHappyPath(t *testing.T) {
	setup := setupPolicyTest(t)
	govKeys := configureGovernance(t, setup.node)

	other1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	other2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	source := []common.Address{setup.node.TeeID(), other1}
	targets := []common.Address{other1, other2}

	req := &types.SetMachinePathListRequest{
		Paths:      singlePathList(source, targets),
		Nonce:      1,
		Signatures: signMachinePathList(t, setup.node, source, targets, 1, govKeys[:2]),
	}
	_, err := setup.executeSetMachinePathList(t, req)
	require.NoError(t, err)

	gotPaths, nonce := setup.node.MachinePaths()
	require.Equal(t, singlePathList(source, targets), gotPaths)
	require.Equal(t, uint64(1), nonce)
}

func TestSetMachinePathListSavesEvenWhenSelfNotOnSourceList(t *testing.T) {
	setup := setupPolicyTest(t)
	govKeys := configureGovernance(t, setup.node)

	// The handler must persist the lists even when this node is absent
	// from them; per-operation source/target checks are enforced
	// downstream, not by SET_BACKUP_IDS.
	other := common.HexToAddress("0x1111111111111111111111111111111111111111")
	source := []common.Address{other}
	target := []common.Address{other}

	req := &types.SetMachinePathListRequest{
		Paths:      singlePathList(source, target),
		Nonce:      1,
		Signatures: signMachinePathList(t, setup.node, source, target, 1, govKeys[:2]),
	}
	_, err := setup.executeSetMachinePathList(t, req)
	require.NoError(t, err)

	gotPaths, _ := setup.node.MachinePaths()
	require.Equal(t, singlePathList(source, target), gotPaths)
}

func TestSetMachinePathListNonceNotHigher(t *testing.T) {
	setup := setupPolicyTest(t)
	govKeys := configureGovernance(t, setup.node)

	other := common.HexToAddress("0x1111111111111111111111111111111111111111")
	source := []common.Address{setup.node.TeeID()}
	firstTargets := []common.Address{other}

	req1 := &types.SetMachinePathListRequest{
		Paths:      singlePathList(source, firstTargets),
		Nonce:      5,
		Signatures: signMachinePathList(t, setup.node, source, firstTargets, 5, govKeys[:2]),
	}
	_, err := setup.executeSetMachinePathList(t, req1)
	require.NoError(t, err)

	other2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	for _, badNonce := range []uint64{5, 3, 0} {
		targets := []common.Address{other2}
		req := &types.SetMachinePathListRequest{
			Paths:      singlePathList(source, targets),
			Nonce:      badNonce,
			Signatures: signMachinePathList(t, setup.node, source, targets, badNonce, govKeys[:2]),
		}
		_, err := setup.executeSetMachinePathList(t, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not higher than current")
	}

	gotPaths, nonce := setup.node.MachinePaths()
	require.Equal(t, singlePathList(source, firstTargets), gotPaths)
	require.Equal(t, uint64(5), nonce)
}

func TestSetMachinePathListSuccessiveUpdates(t *testing.T) {
	setup := setupPolicyTest(t)
	govKeys := configureGovernance(t, setup.node)

	addr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	addr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	addr3 := common.HexToAddress("0x3333333333333333333333333333333333333333")
	source := []common.Address{setup.node.TeeID()}

	for _, step := range []struct {
		nonce   uint64
		targets []common.Address
	}{
		{1, []common.Address{addr1}},
		{2, []common.Address{addr1, addr2}},
		{10, []common.Address{addr3}},
	} {
		req := &types.SetMachinePathListRequest{
			Paths:      singlePathList(source, step.targets),
			Nonce:      step.nonce,
			Signatures: signMachinePathList(t, setup.node, source, step.targets, step.nonce, govKeys[:2]),
		}
		_, err := setup.executeSetMachinePathList(t, req)
		require.NoError(t, err)

		gotPaths, nonce := setup.node.MachinePaths()
		require.Equal(t, singlePathList(source, step.targets), gotPaths)
		require.Equal(t, step.nonce, nonce)
	}
}

func TestSetMachinePathListInvalidJSON(t *testing.T) {
	setup := setupPolicyTest(t)

	_, err := setup.processor.SetMachinePathList(context.Background(), &types.DirectInstruction{Message: []byte(`{"invalid"`)})
	require.Error(t, err)
}

func TestSetMachinePathListGovernanceNotConfigured(t *testing.T) {
	setup := setupPolicyTest(t)

	source := []common.Address{setup.node.TeeID()}
	targets := []common.Address{common.HexToAddress("0x1111111111111111111111111111111111111111")}
	req := &types.SetMachinePathListRequest{
		Paths: singlePathList(source, targets),
		Nonce: 1,
	}
	_, err := setup.executeSetMachinePathList(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "governance not configured")

	gotPaths, nonce := setup.node.MachinePaths()
	require.Empty(t, gotPaths)
	require.Equal(t, uint64(0), nonce)
}

func TestSetMachinePathListBelowThreshold(t *testing.T) {
	setup := setupPolicyTest(t)
	govKeys := configureGovernance(t, setup.node)

	source := []common.Address{setup.node.TeeID()}
	targets := []common.Address{common.HexToAddress("0x1111111111111111111111111111111111111111")}

	// One valid signature when threshold is 2.
	req := &types.SetMachinePathListRequest{
		Paths:      singlePathList(source, targets),
		Nonce:      1,
		Signatures: signMachinePathList(t, setup.node, source, targets, 1, govKeys[:1]),
	}
	_, err := setup.executeSetMachinePathList(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "governance threshold not reached")

	// No signatures at all.
	req.Signatures = nil
	_, err = setup.executeSetMachinePathList(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "governance threshold not reached")

	gotPaths, nonce := setup.node.MachinePaths()
	require.Empty(t, gotPaths)
	require.Equal(t, uint64(0), nonce)
}

func TestSetMachinePathListDuplicateSignaturesNotCounted(t *testing.T) {
	setup := setupPolicyTest(t)
	govKeys := configureGovernance(t, setup.node)

	source := []common.Address{setup.node.TeeID()}
	targets := []common.Address{common.HexToAddress("0x1111111111111111111111111111111111111111")}

	// Two signatures, but both from the same governance signer — only counts as one.
	sigs := signMachinePathList(t, setup.node, source, targets, 1, []*ecdsa.PrivateKey{govKeys[0], govKeys[0]})
	req := &types.SetMachinePathListRequest{
		Paths:      singlePathList(source, targets),
		Nonce:      1,
		Signatures: sigs,
	}
	_, err := setup.executeSetMachinePathList(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "governance threshold not reached")
}

func TestSetMachinePathListNonGovernanceSigner(t *testing.T) {
	setup := setupPolicyTest(t)
	govKeys := configureGovernance(t, setup.node)

	source := []common.Address{setup.node.TeeID()}
	targets := []common.Address{common.HexToAddress("0x1111111111111111111111111111111111111111")}

	outsider, err := crypto.GenerateKey()
	require.NoError(t, err)

	// One legitimate governance signer + one outsider — outsider is rejected
	// before threshold is evaluated.
	sigs := signMachinePathList(t, setup.node, source, targets, 1, []*ecdsa.PrivateKey{govKeys[0], outsider})
	req := &types.SetMachinePathListRequest{
		Paths:      singlePathList(source, targets),
		Nonce:      1,
		Signatures: sigs,
	}
	_, err = setup.executeSetMachinePathList(t, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a voter")
}

func TestSetMachinePathListSignaturesOverDifferentPayload(t *testing.T) {
	setup := setupPolicyTest(t)
	govKeys := configureGovernance(t, setup.node)

	source := []common.Address{setup.node.TeeID()}
	targets := []common.Address{common.HexToAddress("0x1111111111111111111111111111111111111111")}

	// Signatures cover a different nonce than the one in the request.
	sigs := signMachinePathList(t, setup.node, source, targets, 99, govKeys[:2])
	req := &types.SetMachinePathListRequest{
		Paths:      singlePathList(source, targets),
		Nonce:      1,
		Signatures: sigs,
	}
	_, err := setup.executeSetMachinePathList(t, req)
	require.Error(t, err)
	// Recovered address won't be a governance signer.
	require.Contains(t, err.Error(), "not a voter")
}
