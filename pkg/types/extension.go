package types

type SignRequest struct {
	Message []byte `json:"message"`
}

type SignResponse struct {
	Message   []byte `json:"message"`
	Signature []byte `json:"signature"`
}

type DecryptRequest struct {
	EncryptedMessage []byte `json:"encryptedMessage"`
}

type DecryptResponse struct {
	DecryptedMessage []byte `json:"decryptedMessage"`
}
