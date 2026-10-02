package verifier

import "errors"

var (
	ErrChannelRecord         = errors.New("invalid encrypted record")
	ErrChannelAuthentication = errors.New("encrypted record authentication failed")
	ErrChannelLimit          = errors.New("encrypted record usage limit reached")
	ErrChannelTruncated      = errors.New("encrypted stream ended without completion")
	ErrChannelPending        = errors.New("encrypted session awaits request-start acknowledgements")
	ErrChannelCrypto         = errors.New("encrypted session cryptography failed")
)
