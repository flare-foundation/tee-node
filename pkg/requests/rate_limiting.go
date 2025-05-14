package requests

import (
	"sync"
	"tee-node/pkg/config"

	"github.com/pkg/errors"

	"github.com/ethereum/go-ethereum/common"
)

var RateLimiterActive = NewRateLimiter(config.MAX_PENDING_REQUESTS)
var RateLimiterPast = NewRateLimiter(config.MAX_PENDING_REQUESTS)

type RateLimiter struct {
	maxPendingRequests int

	Validators map[string]*ValidatorState

	// If too many validators are blocked, clear the pending requests (too prevent the system from being frozen)
	LimitHitCounter int // Counter to track how many validators have hit their proposal limit this counting period

	mu sync.RWMutex
}

// ValidatorState tracks the counts for a single validator
type ValidatorState struct {
	Address         common.Address
	PendingRequests int
	// Note: The following two fields can be used to calculate the ratio of completed to proposed requests.
	// Note: This could be used to detect if a validator is malicious or just working incorrectly.
	TotalProposed  int
	TotalCompleted int
}

// NewRequestCounter creates a new request counter with the specified limit
func NewRateLimiter(maxPendingRequests int) *RateLimiter {
	return &RateLimiter{
		maxPendingRequests: maxPendingRequests,
		Validators:         make(map[string]*ValidatorState),
	}
}

// Check if the validator is allowed to propose a new request
func CanProposeNewRequest(signerAddress common.Address, inActivePolicy bool) error {
	var canPropose bool
	var err error
	if inActivePolicy {
		canPropose, err = RateLimiterActive.CanProposeRequest(signerAddress)
	} else {
		// todo: add timer for past policy
		canPropose, err = RateLimiterPast.CanProposeRequest(signerAddress)
	}
	if err != nil {
		return err // The request is new but the validator is not registered
	}
	if !canPropose {
		return errors.New("rate limit exceeded") // The request is new but the rate limit was exceeded
	}

	return nil
}

// IncrementRequestCount increases the pending request count when a request is proposed
func IncrementRequestCount(proposerAddress common.Address, inActivePolicy bool) error {
	if inActivePolicy {
		return RateLimiterActive.IncrementRequestCount(proposerAddress)
	} else {
		return RateLimiterPast.IncrementRequestCount(proposerAddress)
	}
}

// IncrementRequestCount increases the pending request count when a request is proposed
func DecrementRequestCount(proposerAddress common.Address, inActivePolicy bool) error {
	if inActivePolicy {
		return RateLimiterActive.DecrementRequestCount(proposerAddress)
	} else {
		return RateLimiterPast.DecrementRequestCount(proposerAddress)
	}
}

func UpdateRateLimiter(activePolicyVoters []common.Address) {
	RateLimiterPast.mu.Lock()
	// migrate active to past
	RateLimiterPast.Validators = RateLimiterActive.Validators
	RateLimiterPast.LimitHitCounter = RateLimiterActive.LimitHitCounter
	RateLimiterPast.mu.Unlock()

	RateLimiterActive.mu.Lock()
	// initiate new active
	RateLimiterActive.Validators = make(map[string]*ValidatorState)
	RateLimiterActive.LimitHitCounter = 0
	RateLimiterActive.registerValidators(activePolicyVoters)
	RateLimiterActive.mu.Unlock()
}

// registerValidators registers all validators from the active and previous Signing Policy
func (rl *RateLimiter) registerValidators(activePolicyVoters []common.Address) {
	// Clear the state of the rate limiter first
	rl.ClearPendingRequests()

	// Add voters from the active policy to the set
	for _, voterAddress := range activePolicyVoters {
		addVoter(rl, voterAddress)
	}
}

func addVoter(rl *RateLimiter, voterAddress common.Address) {
	// Add the voter to the validators map if they don't exist
	if _, exists := rl.Validators[voterAddress.String()]; !exists {
		rl.Validators[voterAddress.String()] = &ValidatorState{
			Address:         voterAddress,
			PendingRequests: 0,
			TotalProposed:   0,
			TotalCompleted:  0,
		}
	}
}

func (rl *RateLimiter) IncrementRequestCount(proposerAddress common.Address) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	validator, exists := rl.Validators[proposerAddress.String()]
	if !exists {
		return errors.New("validator not registered")
	}

	// Check if the validator has too many pending requests
	if validator.PendingRequests >= rl.maxPendingRequests {
		return errors.New("validator has too many pending requests")
	}

	validator.PendingRequests++
	validator.TotalProposed++

	if validator.PendingRequests == rl.maxPendingRequests {
		rl.LimitHitCounter++

		if rl.LimitHitCounter >= config.LIMIT_HIT_COUNT {
			rl.ClearPendingRequests()
			rl.LimitHitCounter = 0
		}
	}

	return nil
}

// DecrementRequestCount decreases the pending request count when a request is completed (passes voting threshold)
func (rl *RateLimiter) DecrementRequestCount(proposerAddress common.Address) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	validator, exists := rl.Validators[proposerAddress.String()]
	if !exists {
		return errors.New("validator not registered")
	}

	if validator.PendingRequests > 0 {
		validator.PendingRequests--
	}

	validator.TotalCompleted++

	return nil
}

func (rl *RateLimiter) ClearPendingRequests() {
	for _, validator := range rl.Validators {
		validator.PendingRequests = 0
	}
}

// CanProposeRequest checks if a validator can propose a new request
// Returns true if they are under the limit, false otherwise
func (rl *RateLimiter) CanProposeRequest(validatorAddress common.Address) (bool, error) {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	validator, exists := rl.Validators[validatorAddress.String()]
	if !exists {
		return false, errors.New("validator not registered")
	}

	return validator.PendingRequests < rl.maxPendingRequests, nil
}

func ClearRateLimiterState() {
	RateLimiterActive = NewRateLimiter(config.MAX_PENDING_REQUESTS)
	RateLimiterPast = NewRateLimiter(config.MAX_PENDING_REQUESTS)
}
