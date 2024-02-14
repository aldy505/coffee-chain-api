package sessionstore

import (
	"context"
	"errors"
	"time"

	"coffee-chain-api/account"
)

// ErrSessionNotExists indicates that this session that we're querying does not exist.
// It may be because of the session has been expired, or there are no such session at all.
var ErrSessionNotExists = errors.New("session does not exists")

// ErrEmptyToken indicates that the token string value is empty.
var ErrEmptyToken = errors.New("empty token")

// SessionStore provides a generic interface for storing account session. It can be implemented with
// various backends such as in memory, external key-value database, or anything obscure that you can
// think of.
type SessionStore interface {
	Set(ctx context.Context, session account.Account, token string, expiry time.Time) error
	Get(ctx context.Context, token string) (session account.Account, err error)
}
