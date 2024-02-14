package authentication

import (
	"context"

	"coffee-chain-api/account"
)

type validator struct{}

func (v *validator) ValidateSession(ctx context.Context, token string) (account.Account, error) {
	// TODO implement me
	panic("implement me")
}

func NewValidator() (Validator, error) {
	return &validator{}, nil
}
