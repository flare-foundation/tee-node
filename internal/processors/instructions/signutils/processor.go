package signutils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/flare-foundation/go-flare-common/pkg/policy"
	csigning "github.com/flare-foundation/go-flare-common/pkg/signing"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/xrpl"
	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/router/queue"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/internal/wallets"
	"github.com/flare-foundation/tee-node/pkg/types"
)

type Processor struct {
	*wallets.Storage
	node.IdentifierAndSigner
	proxyURL       *settings.ProxyURLMutex
	activeRoutines atomic.Int64
}

// NewProcessor creates a signing instruction processor backed by the provided
// wallet storage and TEE node.
func NewProcessor(iAndS node.IdentifierAndSigner, wStorage *wallets.Storage, proxyURL *settings.ProxyURLMutex) Processor {
	return Processor{
		Storage:             wStorage,
		IdentifierAndSigner: iAndS,
		proxyURL:            proxyURL,
	}
}

// SignXRPLPayment signs the XRP Ledger payment described in the instruction for
// each fee schedule entry upfront, then spawns a goroutine that posts the
// cumulative signed transaction set to the proxy after each entry's scheduled
// delay elapses.
func (p *Processor) SignXRPLPayment(
	ctx context.Context,
	submissionTag types.SubmissionTag,
	dataFixed *instruction.DataFixed,
	_ []hexutil.Bytes,
	_ []common.Address,
	_ *policy.SigningPolicy,
) ([]byte, []byte, error) {
	inst, err := types.ParsePaymentInstruction(dataFixed)
	if err != nil {
		return nil, nil, err
	}

	entries, err := xrpl.ParseFeeEntries(inst.FeeSchedule)
	if err != nil {
		return nil, nil, err
	}
	if len(entries) == 0 {
		return nil, nil, errors.New("fee schedule is empty")
	}
	if len(entries) > settings.MaxFeeEntries {
		return nil, nil, fmt.Errorf("fee schedule has %d entries, maximum is %d", len(entries), settings.MaxFeeEntries)
	}
	for i, entry := range entries {
		if entry.Delay > settings.MaxFeeScheduleTime {
			return nil, nil, fmt.Errorf("fee entry %d delay %v exceeds maximum %v", i, entry.Delay, settings.MaxFeeScheduleTime)
		}
	}

	teeID := p.TeeID()
	keyIDs := make([]uint64, 0, len(inst.TeeIdKeyIdPairs))
	for _, pair := range inst.TeeIdKeyIdPairs {
		if pair.TeeId == teeID {
			keyIDs = append(keyIDs, pair.KeyId)
		}
	}
	if len(keyIDs) == 0 {
		return nil, nil, errors.New("no keys for signing")
	}

	p.RLock()
	privateKeys, err := loadPrivateKeys(p.Storage, inst.WalletId, keyIDs, dataFixed)
	p.RUnlock()
	if err != nil {
		return nil, nil, err
	}

	signedTxs := make(types.XRPSignResponse, len(entries))
	for i := range entries {
		signedTxs[i], err = buildSignedTx(inst, privateKeys, i)
		if err != nil {
			return nil, nil, err
		}
	}

	switch submissionTag {
	case types.Threshold:
		if p.proxyURL == nil {
			return nil, nil, errors.New("proxy URL not configured")
		}
		p.proxyURL.RLock()
		proxyURL := p.proxyURL.URL
		p.proxyURL.RUnlock()
		if proxyURL == "" {
			return nil, nil, errors.New("proxy URL not set")
		}

		chainID, err := p.ChainID()
		if err != nil {
			return nil, nil, err
		}

		// Reserve a slot atomically: a separate Load-then-Add would let two
		// concurrent callers both observe a count below the cap and both proceed.
		if n := p.activeRoutines.Add(1); n > int64(settings.MaxSignGoroutines) {
			p.activeRoutines.Add(-1)
			return nil, nil, errors.New("maximum number of concurrent sign goroutines reached")
		}

		go func() {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Errorf("sign schedule goroutine panic: %v", rec)
				}
				p.activeRoutines.Add(-1)
			}()
			startTime := time.Now()
			for i, entry := range entries {
				time.Sleep(time.Until(startTime.Add(entry.Delay)))

				responseData, err := json.Marshal(signedTxs[:i+1])
				if err != nil { // this should never happen since the data is well-formed, but we handle it just in case
					logger.Errorf("sign schedule: try %d error marshaling response: %v", i, err)
					return
				}

				var status uint8
				if i < len(entries)-1 {
					status = 3 + uint8(i) // status 3 for the first response, 4 for the second, etc.
				} else {
					status = 1 // final response after all entries
				}
				result := types.ActionResult{
					ID:            dataFixed.InstructionID,
					SubmissionTag: submissionTag,
					Status:        status,
					Version:       settings.EncodingVersion,
					OPType:        dataFixed.OPType,
					OPCommand:     dataFixed.OPCommand,
					Data:          responseData,
				}

				signHash, err := csigning.NewPayload(csigning.TEEActionResult, chainID, common.BytesToHash(result.Hash())).Hash()
				if err != nil {
					logger.Errorf("sign schedule: try %d computing sign hash error: %v", i, err)
					return
				}
				sig, err := p.Sign(signHash[:])
				if err != nil { // this should never happen since we already signed the same data during pre-processing, but we handle it just in case
					logger.Errorf("sign schedule: try %d signing result error: %v", i, err)
					return
				}

				response := &types.ActionResponse{
					Result:    result,
					Signature: sig,
				}

				if err := queue.PostActionResponse(proxyURL+"/result", response); err != nil {
					logger.Errorf("sign schedule: try %d error posting result: %v", i, err)
					continue
				}
			}
		}()

	case types.End:
	default:
		return nil, nil, errors.New("unexpected submission tag")
	}

	return []byte{}, nil, nil
}
