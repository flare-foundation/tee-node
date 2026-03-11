package node

import "github.com/ethereum/go-ethereum/common"

type Signer interface {
	Sign([]byte) ([]byte, error)
}

type Decrypter interface {
	Decrypt([]byte) ([]byte, error)
}

type Identifier interface {
	TeeID() common.Address
}

type Informer interface {
	Info() Info
}

type Configurer interface {
	SetOwner(common.Address) error
	SetExtensionID(common.Hash) error
}

type IdentifierAndSigner interface {
	Identifier
	Signer
}

type IdentifierSignerAndDecrypter interface {
	Identifier
	Signer
	Decrypter
}

type InformerAndSigner interface {
	Informer
	Signer
}
