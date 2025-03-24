package requests

import (
	"encoding/hex"
	"sync"
	"tee-node/pkg/config"
	"tee-node/pkg/policy"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
)

// The following is the main requestCounterStorage, holding requests that need to reach a threshold
// before being executed.
var requestCounterStorage *RequestCounterStorage

// Initialize storages for each request type
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

	Done   bool
	Result []byte

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

	requestCounter, exists, err := GetRequestCounterByHash(requestHash)
	if err != nil {
		return nil, err
	}
	if exists {
		return requestCounter, nil
	} else {
		return CreateAndStoreRequestCounter(requestHash, request)
	}
}

func GetRequestCounterByHash(requestHash string) (*RequestCounter, bool, error) {
	requestCounterStorage.Lock()
	defer requestCounterStorage.Unlock()
	requestCounter, ok := requestCounterStorage.Storage[requestHash]
	if !ok {
		return nil, false, nil
	}

	return requestCounter, true, nil
}

func CreateAndStoreRequestCounter(requestHash string, request *instruction.Data) (*RequestCounter, error) {
	requestCounter := NewRequestCounter(request)

	requestCounterStorage.Lock()
	requestCounterStorage.Storage[requestHash] = requestCounter
	requestCounterStorage.Unlock()

	return requestCounter, nil
}

func NewRequestCounter(request *instruction.Data) *RequestCounter {
	requestPolicy := policy.GetSigningPolicy(uint32(request.RewardEpochID.Uint64()))
	threshold := requestPolicy.Threshold // todo: for now just read from policy

	return &RequestCounter{
		Request:                 &request.DataFixed,
		RequestPolicy:           requestPolicy,
		Threshold:               threshold,
		RequestSignatures:       make(map[common.Address][]byte),
		RequestVariableMessages: make(map[common.Address][]byte),
	}
}

// Check that the request policy is still active (within config.ACTIVE_POLICY_COUNT) of the active policy reward epoch id
func (r *RequestCounter) CheckActive(requestPolicy *policy.SigningPolicy) bool {
	return policy.ActiveSigningPolicy.RewardEpochId-requestPolicy.RewardEpochId <= config.ACTIVE_POLICY_COUNT // todo maybe based on name it should be strictly smaller
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
func DestoryState() {
	requestCounterStorage = InitRequestCounterStorage()
}
