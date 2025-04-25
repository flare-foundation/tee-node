package types

type InstructionResponse struct {
	ResponseBase
	Finalized bool // Note: leaving this in for now, because it's used in the tests
}

type InstructionResultRequest struct {
	Challenge     string
	InstructionId string
}

type InstructionResultResponse struct {
	ResponseBase
	Data []byte
}

type InstructionStatusResponse struct {
	ResponseBase
	Data InstructionStatusData
}

type InstructionStatusData struct {
	VoteResults []VoteResult
	Status      string
	ErrorLog    string
}

type VoteResult struct {
	NumberOfVotes uint16
	TotalWeight   uint16
}

type RewardingDataResponse struct {
	ResponseBase
	Data []byte
}
