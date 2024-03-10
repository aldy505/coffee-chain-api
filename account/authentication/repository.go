package authentication

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"coffee-chain-api/account"
	"coffee-chain-api/account/accountstore"
	"coffee-chain-api/account/jwt"
	"coffee-chain-api/account/sessionstore"
)

type Repository struct {
	db                  *sql.DB
	accessSessionStore  sessionstore.SessionStore
	refreshSessionStore sessionstore.SessionStore
	accountStore        accountstore.AccountStore
	jwt                 *jwt.AuthJwt
}

func (r *Repository) Login(ctx context.Context, email string, plainPassword string) (accessToken string, refreshToken string, expiredAt time.Time, err error) {
	basicUserAccount := account.NewBasicAccount(account.Profile{Email: email}, account.TypeUnspecified, 0)

	passwordValidated, err := r.accountStore.ValidatePassword(ctx, basicUserAccount, plainPassword)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("validating password: %w", err)
	}

	if !passwordValidated {
		return "", "", time.Time{}, ErrInvalidAuthentication
	}

	properUserAccount, err := r.accountStore.GetByEmail(ctx, email)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("acquiring account by email: %w", err)
	}

	accessToken, refreshToken, err = r.jwt.Sign(properUserAccount.GetProfile().ID)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("signing jsonwebtoken: %w", err)
	}

	accessTokenExpiredAt := time.Now().Add(time.Hour)
	err = r.accessSessionStore.Set(ctx, properUserAccount, accessToken, accessTokenExpiredAt)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("storing session on store: %w", err)
	}

	refreshTokenExpiredAt := time.Now().Add(time.Hour * 24 * 30)
	err = r.refreshSessionStore.Set(ctx, properUserAccount, refreshToken, refreshTokenExpiredAt)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("storing session on store: %w", err)
	}

	return accessToken, refreshToken, accessTokenExpiredAt, nil
}

func (r *Repository) Logout(ctx context.Context, token string) error {
	err := r.accessSessionStore.Remove(ctx, token)
	if err != nil {
		return fmt.Errorf("removing session: %w", err)
	}

	return nil
}

func (r *Repository) ValidateSession(ctx context.Context, token string) (account.Account, error) {
	if token == "" {
		return nil, ErrInvalidAuthentication
	}

	userAccount, err := r.accessSessionStore.Get(ctx, token)
	if err != nil {
		if errors.Is(err, sessionstore.ErrEmptyToken) || errors.Is(err, sessionstore.ErrSessionNotExists) {
			return nil, ErrInvalidAuthentication
		}

		return nil, fmt.Errorf("acquiring session: %w", err)
	}

	return userAccount, nil
}

func (r *Repository) Refresh(ctx context.Context, refreshToken string) (accessToken string, expiredAt time.Time, err error) {
	if refreshToken == "" {
		return "", time.Time{}, ErrInvalidAuthentication
	}

	userAccount, err := r.refreshSessionStore.Get(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, sessionstore.ErrEmptyToken) || errors.Is(err, sessionstore.ErrSessionNotExists) {
			return "", time.Time{}, ErrInvalidAuthentication
		}

		return "", time.Time{}, fmt.Errorf("acquiring session: %w", err)
	}

	accessToken, _, err = r.jwt.Sign(userAccount.GetProfile().ID)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("signing jsonwebtoken: %w", err)
	}

	accessTokenExpiredAt := time.Now().Add(time.Hour)
	err = r.accessSessionStore.Set(ctx, userAccount, accessToken, accessTokenExpiredAt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("storing session on store: %w", err)
	}

	return accessToken, accessTokenExpiredAt, nil
}

func NewAuthenticationRepository(accessSessionStore sessionstore.SessionStore, refreshSessionStore sessionstore.SessionStore, accountStore accountstore.AccountStore) (AuthenticatorAndValidator, error) {
	if accessSessionStore == nil {
		return nil, fmt.Errorf("accessSessionStore is nil")
	}
	if refreshSessionStore == nil {
		return nil, fmt.Errorf("refreshSessionStore is nil")
	}
	if accountStore == nil {
		return nil, fmt.Errorf("accountStore is nil")
	}

	return &Repository{
		accessSessionStore:  accessSessionStore,
		refreshSessionStore: refreshSessionStore,
		accountStore:        accountStore,
	}, nil
}
