package requests

import (
	"encoding/hex"
	"errors"
	"sync"
	"tee-node/pkg/policy"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
)

// The following is the main requestCounterStorage, holding requests that need to reach a threshold
// before being executed.
var requestCounterStorage *RequestCounterStorage

func init() {
	requestCounterStorage = InitRequestCounterStorage()
}

type RequestCounterStorage struct {
	Storage map[string]*RequestCounter

	sync.Mutex
}

type RequestCounter struct {
	Request *instruction.DataFixed

	RequestVariableMessages map[common.Address][]byte
	RequestSignatures       map[common.Address][]byte
	RequestPolicy           *policy.SigningPolicy
	Threshold               uint16

	Proposer common.Address
	Done     bool
	Result   []byte

	sync.Mutex
}

func InitRequestCounterStorage() *RequestCounterStorage {
	return &RequestCounterStorage{Storage: make(map[string]*RequestCounter)}
}

func GetRequestCounter(request *instruction.Data) (*RequestCounter, error) {
	hash, err := request.HashFixed()
	if err != nil {
		return nil, err
	}
	requestHash := hex.EncodeToString(hash[:])

	requestCounter, exists := GetRequestCounterByHash(requestHash)
	if !exists {
		return nil, errors.New("request counter not found")
	}

	return requestCounter, nil
}

func GetRequestCounterByHash(requestHash string) (*RequestCounter, bool) {
	requestCounterStorage.Lock()
	defer requestCounterStorage.Unlock()
	requestCounter, exists := requestCounterStorage.Storage[requestHash]
	if !exists {
		return nil, exists
	}

	return requestCounter, exists
}

func RemoveRequestCounterByHash(requestHash string) {
	requestCounterStorage.Lock()
	defer requestCounterStorage.Unlock()

	delete(requestCounterStorage.Storage, requestHash)
}

func CreateAndStoreRequestCounter(request *instruction.Data, proposer common.Address) *RequestCounter {
	hash, _ := request.HashFixed() // TODO: handle error? I think this is checked implicitly before this call
	requestHash := hex.EncodeToString(hash[:])

	requestCounter := NewRequestCounter(request, proposer)

	requestCounterStorage.Lock()
	requestCounterStorage.Storage[requestHash] = requestCounter
	requestCounterStorage.Unlock()

	return requestCounter
}

func NewRequestCounter(request *instruction.Data, proposer common.Address) *RequestCounter {
	requestPolicy := policy.GetSigningPolicy(uint32(request.RewardEpochID.Uint64()))
	threshold := requestPolicy.Threshold // todo: for now just read from policy

	return &RequestCounter{
		Request:                 &request.DataFixed,
		RequestPolicy:           requestPolicy,
		Threshold:               threshold,
		RequestSignatures:       make(map[common.Address][]byte),
		RequestVariableMessages: make(map[common.Address][]byte),
		Proposer:                proposer,
	}
}

// Check that the request policy is still active, meaning either the active policy or the withing the 5 minute transition period
func (r *RequestCounter) CheckActive() error {
	rewardEpochId := r.RequestPolicy.RewardEpochId
	activePolicyId := policy.ActiveSigningPolicy.RewardEpochId

	if rewardEpochId == activePolicyId || rewardEpochId == activePolicyId-1 {
		return nil
	}

	return errors.New("policy not active")
}

func (r *RequestCounter) CurrentWeight() uint16 {
	return policy.WeightOfSigners(r.RequestSignatures, r.RequestPolicy)
}

func (r *RequestCounter) ThresholdReached() bool {
	currentWeight := r.CurrentWeight()

	return currentWeight >= r.Threshold
}

func (r *RequestCounter) AddRequestSignature(reqSigner common.Address, reqSignature []byte) {
	r.RequestSignatures[reqSigner] = reqSignature
}

func (r *RequestCounter) AddRequestVariableMessage(reqSigner common.Address, reqVariableMessage []byte) {
	r.RequestVariableMessages[reqSigner] = reqVariableMessage
}

func (r *RequestCounter) Signatures() [][]byte {
	signatures := make([][]byte, 0)
	for _, e := range r.RequestSignatures {
		signatures = append(signatures, e)
	}

	return signatures
}

// Note: We need this for distributing rewards to the signers
// Note: Not sure yet what API this should have, but this is a start
func (r *RequestCounter) GetRequestSigners() []*common.Address {
	var signers []*common.Address = make([]*common.Address, 0)
	for signer := range r.RequestSignatures {
		signers = append(signers, &signer)
	}
	return signers
}

// Note: This is useful for tests, but it would also be useful for upgrades, where a TEE get's shutdown.
func DestroyState() {
	requestCounterStorage = InitRequestCounterStorage()

	DestroyGarbageCollector()
	ClearRateLimiterState()
}
