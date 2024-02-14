package authentication

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"coffee-chain-api/account"
	"coffee-chain-api/account/sessionstore"
)

type Repository struct {
	db           *sql.DB
	sessionStore sessionstore.SessionStore
}

func (r *Repository) getUserAccountByEmail(ctx context.Context, email string) account.Account

func (r *Repository) Login(ctx context.Context, email string, plainPassword string) (token string, expiredAt time.Time, err error) {
	// TODO implement me
	panic("implement me")
}

func (r *Repository) Logout(ctx context.Context, token string) error {
	// TODO implement me
	panic("implement me")
}

func (r *Repository) ValidateSession(ctx context.Context, token string) (account.Account, error) {
	// TODO implement me
	panic("implement me")
}

func NewAuthenticationRepository(db *sql.DB, sessionStore sessionstore.SessionStore) (AuthenticatorAndValidator, error) {
	if db == nil {
		return nil, fmt.Errorf("db is nil")
	}
	if sessionStore == nil {
		return nil, fmt.Errorf("sessionStore is nil")
	}

	return &Repository{
		db:           db,
		sessionStore: sessionStore,
	}, nil
}
