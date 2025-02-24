package requests

import (
	"crypto/ecdsa"
	"encoding/hex"
	"sync"
	"tee-node/internal/policy"
	"tee-node/internal/signing"
	"tee-node/internal/utils"
	"tee-node/internal/wallets"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"golang.org/x/exp/slices"
)

// The following variables are the main storage, holding requests that need to reach a threshold
// before being executed. Each request should have a unique string message.
var NewWalletRequestsStorage = InitRequestCounterStorage[wallets.NewWalletRequest]()
var DeleteWalletRequestsStorage = InitRequestCounterStorage[wallets.DeleteWalletRequest]()
var SplitWalletRequestsStorage = InitRequestCounterStorage[wallets.SplitWalletRequest]()
var RecoverWalletRequestsStorage = InitRequestCounterStorage[wallets.RecoverWalletRequest]()

var SignPaymentRequestsStorage = InitRequestCounterStorage[signing.SignPaymentRequest]()

type RequestCounter[T Request] struct {
	Request T

	Requesters map[common.Address]bool // Note: Maybe Signers would be a better name?
	PolicyHash string
	Done       bool
	Result     []byte
}

type RequestCounterStorage[T Request] struct {
	Storage map[string]*RequestCounter[T]

	sync.Mutex
}

func InitRequestCounterStorage[T Request]() RequestCounterStorage[T] {
	return RequestCounterStorage[T]{Storage: make(map[string]*RequestCounter[T])}
}

// todo: not sure if this makes sense, just trying to unify
type Request interface {
	Message() string
	Check() error
}

func Sign(r Request, privKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := crypto.Keccak256([]byte(r.Message()))
	signature, err := utils.Sign(hash, privKey)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func CheckSignature(r Request, signature []byte) (common.Address, error) {
	hash := crypto.Keccak256([]byte(r.Message()))

	pubKey, err := crypto.SigToPub(accounts.TextHash(hash), signature)
	if err != nil {
		return common.Address{}, err
	}
	address := crypto.PubkeyToAddress(*pubKey)
	if !slices.Contains(policy.ActiveSigningPolicy.Voters, address) {
		return common.Address{}, errors.New("not a voter")
	}

	return address, nil
}

func ProcessRequest[T Request](request T, signature []byte, requestCounterStorage *RequestCounterStorage[T]) (*RequestCounter[T], bool, error) {
	err := request.Check()
	if err != nil {
		return nil, false, err
	}

	requestCounterStorage.Lock()
	if _, ok := requestCounterStorage.Storage[request.Message()]; !ok {
		requestCounterStorage.Storage[request.Message()] = NewRequestCounter(request)
	}
	requestCounter := requestCounterStorage.Storage[request.Message()]
	if !requestCounter.CheckActive() {
		return nil, false, errors.New("not active")
	}

	providerAddress, err := CheckSignature(request, signature)
	if err != nil {
		return nil, false, err
	}

	requestCounter.AddRequester(providerAddress)

	thresholdReached := requestCounter.ThresholdReached()
	requestCounterStorage.Unlock()

	return requestCounter, thresholdReached, nil
}

func NewRequestCounter[T Request](request T) *RequestCounter[T] {
	return &RequestCounter[T]{
		Request:    request,
		Requesters: make(map[common.Address]bool),
		PolicyHash: hex.EncodeToString(policy.ActiveSigningPolicyHash), // todo, maybe make requester specify this
	}
}

func (r *RequestCounter[T]) CheckActive() bool {
	// Note: What if we initialize the request with a policy, but then the active signing policy changes?
	// Note: Then this would fail, but it probably shouldn't, or we should have a way to handle it.
	return hex.EncodeToString(policy.ActiveSigningPolicyHash) == r.PolicyHash
}

func (r *RequestCounter[T]) Threshold() uint16 {
	return policy.ActiveSigningPolicy.Threshold
}

func (r *RequestCounter[T]) CurrentWeight() uint16 {
	currentWeight := uint16(0)
	for i, voter := range policy.ActiveSigningPolicy.Voters {
		if _, ok := r.Requesters[voter]; ok {
			currentWeight += policy.ActiveSigningPolicy.Weights[i]
		}
	}

	return currentWeight
}

func (r *RequestCounter[T]) ThresholdReached() bool {
	currentWeight := r.CurrentWeight()
	threshold := r.Threshold()

	return currentWeight >= threshold
}

func (r *RequestCounter[T]) AddRequester(requester common.Address) {
	r.Requesters[requester] = true
}
