package authentication

import (
	"context"
	"errors"
	"time"

	"coffee-chain-api/account"
)

var ErrInvalidAuthentication = errors.New("invalid authentication")

type Authenticator interface {
	Login(ctx context.Context, email string, plainPassword string) (accessToken string, refreshToken string, expiredAt time.Time, err error)
	Logout(ctx context.Context, accessToken string) error
	Refresh(ctx context.Context, refreshToken string) (accessToken string, expiredAt time.Time, err error)
}

type Validator interface {
	ValidateSession(ctx context.Context, accessToken string) (account.Account, error)
}

type AuthenticatorAndValidator interface {
	Authenticator
	Validator
}
