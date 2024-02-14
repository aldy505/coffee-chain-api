package authentication

import (
	"context"
	"time"

	"coffee-chain-api/account"
)

type Authenticator interface {
	Login(ctx context.Context, email string, plainPassword string) (token string, expiredAt time.Time, err error)
	Logout(ctx context.Context, token string) error
}

type Validator interface {
	ValidateSession(ctx context.Context, token string) (account.Account, error)
}

type AuthenticatorAndValidator interface {
	Authenticator
	Validator
}
