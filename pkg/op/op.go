package op

import (
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

type Type string

const (
	Reg    Type = "F_REG"
	Wallet Type = "F_WALLET"
	Get    Type = "F_GET"
	Policy Type = "F_POLICY"
	XRP    Type = "F_XRP"
	BTC    Type = "F_BTC"
	FTDC   Type = "F_FTDC"
)

type Command string

const (
	// ReplicateFrom    OPCommand = "REPLICATE_FROM".

	TEEAttestation Command = "TEE_ATTESTATION"

	// ToPauseForUpdate OPCommand = "TO_PAUSE_FOR_UPGRADE".

	KeyDataProviderRestore     Command = "KEY_DATA_PROVIDER_RESTORE"
	KeyDataProviderRestoreTest Command = "KEY_DATA_PROVIDER_RESTORE_TEST"
	KeyDelete                  Command = "KEY_DELETE"
	KeyGenerate                Command = "KEY_GENERATE"

	KeyInfo   Command = "KEY_INFO"
	TEEBackup Command = "TEE_BACKUP"
	TEEInfo   Command = "TEE_INFO"

	InitializePolicy Command = "INITIALIZE_POLICY"
	UpdatePolicy     Command = "UPDATE_POLICY"

	Pay     Command = "PAY"
	Reissue Command = "REISSUE"

	Prove Command = "PROVE"
)

var validPairs = map[Type]map[Command]bool{
	Reg: {
		TEEAttestation: true,
	},
	Wallet: {
		KeyDataProviderRestore:     true,
		KeyDataProviderRestoreTest: true,
		KeyDelete:                  true,
		KeyGenerate:                true,
	},
	Get: {
		KeyInfo:   true,
		TEEBackup: true,
		TEEInfo:   true,
	},
	Policy: {
		InitializePolicy: true,
		UpdatePolicy:     true,
	},
	XRP: {
		Pay:     true,
		Reissue: true,
	},
	BTC: {
		Pay:     true,
		Reissue: true,
	},
	FTDC: {
		Prove: true,
	},
}

// IsValid checks whether t is a valid OPType.
func (t Type) IsValid() bool {
	_, ok := validPairs[t]
	return ok
}

// Hash returns utf8 encoding of t padded to 32 bytes.
func (t Type) Hash() common.Hash {
	return common.BytesToHash(common.RightPadBytes([]byte(t), 32))
}

// IsValid checks whether c is a valid OPCommand.
func (c Command) IsValid() bool {
	for _, m := range validPairs {
		_, ok := m[c]
		if ok {
			return true
		}
	}

	return false
}

// Hash returns utf8 encoding of c padded to 32 bytes.
func (c Command) Hash() common.Hash {
	return common.BytesToHash(common.RightPadBytes([]byte(c), 32))
}

// StringToOPTypeSafe converts string to op.Type and indicates whether it is a valid op.Type.
func StringToOPTypeSafe(s string) (Type, bool) {
	t := Type(s)

	return t, t.IsValid()
}

// HashToOPTypeSafe converts hash to op.Type and indicates whether it is a valid op.Type.
func HashToOPTypeSafe(h common.Hash) (Type, bool) {
	s := strings.TrimRight(string(h.Bytes()), "\x00")

	return StringToOPTypeSafe(s)
}

// HashToOPTypeSafe converts hash to op.Type and indicates whether it is a valid op.Type.
func HashToOPType(h common.Hash) Type {
	s := strings.TrimRight(string(h.Bytes()), "\x00")

	return Type(s)
}

// StringToOPCommand converts string to op.Command and indicates whether it is a valid op.Command.
func StringToOPCommandSafe(s string) (Command, bool) {
	c := Command(s)

	for _, m := range validPairs {
		_, ok := m[c]
		if ok {
			return c, true
		}
	}

	return c, false
}

// HashToOPCommandSafe converts hash to op.Command and indicates whether it is a valid op.Command.
func HashToOPCommandSafe(h common.Hash) (Command, bool) {
	s := strings.TrimRight(string(h.Bytes()), "\x00")

	return StringToOPCommandSafe(s)
}

// HashToOPCommand converts hash to op.Command.
func HashToOPCommand(h common.Hash) Command {
	s := strings.TrimRight(string(h.Bytes()), "\x00")

	return Command(s)
}

// IsValidPair checks whether (t,c) is a valid pair of op.Type and opCommand.
func IsValidPair(t Type, c Command) bool {
	cs, ok := validPairs[t]
	if !ok {
		return false
	}
	_, ok = cs[c]
	return ok
}

// IsValid checks that hashes represent a valid pair of op.Type and op.Command.
func IsValid(opType common.Hash, opCommand common.Hash) bool {
	t := Type(strings.TrimRight(string(opType.Bytes()), "\x00"))
	c := Command(strings.TrimRight(string(opCommand.Bytes()), "\x00"))

	return IsValidPair(t, c)
}
