package accountstore

import (
	"context"
	"errors"

	"coffee-chain-api/account"
)

var ErrNotFound = errors.New("account not found")
var ErrDuplicateEntry = errors.New("duplicate account entry")

type RawAccount struct {
	Name          string
	Email         string
	PlainPassword string
	Type          account.Type
}

type AccountStore interface {
	GetByEmail(ctx context.Context, email string) (account.Account, error)
	Insert(ctx context.Context, rawAccount RawAccount) error
	DeleteByEmail(ctx context.Context, email string) error
	ValidatePassword(ctx context.Context, account2 account.Account, plainPassword string) (bool, error)
	// TODO: Update partial
}
