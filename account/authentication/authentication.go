package authentication

import (
	"context"
	"time"

	"coffee-chain-api/account"
)

type Session struct {
	Token     string
	ExpiredAt time.Time
}

type Authenticator interface {
	Login(ctx context.Context, username string, plainPassword string) (Session, error)
	Logout(ctx context.Context, token string) error
}

type Validator interface {
	ValidateSession(ctx context.Context, token string) (account.Account, error)
}
