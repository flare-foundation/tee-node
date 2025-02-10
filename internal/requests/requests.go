package requests

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"tee-node/internal/policy"
	"tee-node/internal/utils"
	"tee-node/internal/wallets"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"golang.org/x/exp/slices"
)

// The following variables are the main storage holding requests that need to reach a threshold
// before being executed. Each request should have a unique string message.
var NewWalletRequestsStorage = make(RequestCounterStorage[wallets.NewWalletRequest])
var SplitWalletRequestsStorage = make(RequestCounterStorage[wallets.SplitWalletRequest])
var RecoverWalletRequestsStorage = make(RequestCounterStorage[wallets.RecoverWalletRequest])

type RequestCounter[T Request] struct {
	Request T

	Requesters map[common.Address]bool
	PolicyHash string
	Done       bool
}

type RequestCounterStorage[T Request] map[string]*RequestCounter[T]

// todo: not sure if this makes sense, just trying to unify
type Request interface {
	Message() string
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
	fmt.Println(address)
	if !slices.Contains(policy.ActiveSigningPolicy.Voters, address) {
		return common.Address{}, err
	}

	return address, nil
}

func ProcessRequest[T Request](request T, signature []byte, requestCounterStorage map[string]*RequestCounter[T]) (*RequestCounter[T], bool, error) {
	if _, ok := requestCounterStorage[request.Message()]; !ok {
		requestCounterStorage[request.Message()] = NewRequestCounter(request)
	}
	requestCounter := requestCounterStorage[request.Message()]
	if !requestCounter.CheckActive() {
		return nil, false, errors.New("not active")
	}

	providerAddress, err := CheckSignature(request, signature)
	if err != nil {
		return nil, false, err
	}
	requestCounter.AddRequester(providerAddress)

	thresholdReached := requestCounter.ThresholdReached()

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
	fmt.Println(currentWeight, threshold)

	return currentWeight >= threshold
}

func (r *RequestCounter[T]) AddRequester(requester common.Address) {
	r.Requesters[requester] = true
}
