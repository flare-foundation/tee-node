package governanceactions

import (
	"tee-node/api/types"
	"tee-node/pkg/node"
	"tee-node/pkg/utils"

	"github.com/pkg/errors"

	"github.com/ethereum/go-ethereum/common"
)

func Pause(message types.PauseTeeMessage, signatures [][]byte) error {
	isPaused := IsTeePaused()
	if isPaused {
		return errors.New("node is already paused")
	}

	// This is how we prevent replay attacks
	pausingNonce := GetTeePausingNonce()
	if pausingNonce != message.PausingNonce {
		return errors.New("pausing nonce mismatch")
	}

	err := verifyValidTeeId(message.TeeId)
	if err != nil {
		return err
	}

	pausingAddresses := GetTeePausingAddresses()

	err = utils.VerifyPauserSignature(message, pausingAddresses, signatures)
	if err != nil {
		return err
	}

	PauseTeeInternal()
	return nil
}

func Resume(message types.ResumeTeeMessage, signatures [][]byte) error {
	isPaused := IsTeePaused()
	if !isPaused {
		return errors.New("node is not paused")
	}

	err := verifyGovernanceMessage(message, signatures)
	if err != nil {
		return err
	}

	pausingNonce := GetTeePausingNonce()

	for _, pair := range message.ResumePairs {
		if pair.PausingNonce == pausingNonce {
			return resumeTee(pair.TeeId)
		}
	}
	return errors.New("no matching pausing nonce found")
}

func SetPausingAddresses(message types.PausingAddressSetMessage, signatures [][]byte) error {
	isPaused := IsTeePaused()
	if isPaused {
		return errors.New("node is paused")
	}

	err := verifyGovernanceMessage(message, signatures)
	if err != nil {
		return err
	}

	nodeId := node.GetNodeInfo()
	for _, setting := range message.PausingAddressSettings {
		if setting.TeeId == nodeId.TeeId {
			return updatePausingAddresses(setting)
		}
	}

	return nil
}

func NewUpgradePath(message types.UpgradePathMessage, signatures [][]byte) error {
	isPaused := IsTeePaused()
	if isPaused {
		return errors.New("node is paused")
	}

	err := verifyGovernanceMessage(message, signatures)
	if err != nil {
		return err
	}

	for _, upgradePath := range message.UpgradePaths {
		node.AppendUpgradePath(upgradePath)
	}
	return nil
}

func BanVersion(message types.BanVersionMessage, signatures [][]byte) error {
	isPaused := IsTeePaused()
	if isPaused {
		return errors.New("node is paused")
	}

	err := verifyGovernanceMessage(message, signatures)
	if err != nil {
		return err
	}

	for _, version := range message.CodeVersions {
		node.AddBannedVersion(version)
	}
	return nil
}

func resumeTee(teeId common.Address) error {
	err := verifyValidTeeId(teeId)
	if err != nil {
		return err
	}

	UnpauseTeeInternal()
	return nil
}

func updatePausingAddresses(setting types.PausingAddressSettings) error {
	err := verifyValidTeeId(setting.TeeId)
	if err != nil {
		return err
	}

	lastPauserAddressSetupNonce := GetTeePausingAddressSetupNonce()

	// If lastPauserAddressSetupNonce >= setting.PauserAddressSetupNonce, return an error
	if lastPauserAddressSetupNonce.Cmp(&setting.PauserAddressSetupNonce) != -1 {
		return errors.New("new pauser address setup nonce is too small")
	}

	UpdatePausingAddressesTeeInternal(setting.PausingAddresses, setting.PauserAddressSetupNonce)

	return nil
}

func verifyGovernanceMessage(message types.GovernanceMessage, signatures [][]byte) error {
	valid, err := node.CheckGovernanceHash(message.GovPolicyHash())
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("governance hash mismatch")
	}

	messageHash, err := message.Hash()
	if err != nil {
		return err
	}

	governancePolicy := node.GetGovernancePolicy()
	isThresholdMet, err := utils.VerifyThresholdSignatures(messageHash[:], governancePolicy.Signers, signatures, governancePolicy.Threshold)
	if err != nil {
		return err
	}
	if !isThresholdMet {
		return errors.New("threshold not met")
	}

	return nil
}

func verifyValidTeeId(teeId common.Address) error {
	nodeId := node.GetTeeId()
	if teeId != nodeId {
		return errors.New("teeID mismatch")
	}

	return nil
}
