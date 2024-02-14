package accountstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"coffee-chain-api/account"
	"coffee-chain-api/account/password"

	"github.com/rs/zerolog/log"
)

type userAccountsTable struct {
	ID             int64
	Name           string
	Email          string
	HashedPassword string `json:"-"`
	Gender         int8
	Type           int8
	EmailValidated bool
	CreatedAt      time.Time
	CreatedBy      string
	UpdatedAt      time.Time
	UpdatedBy      string
}

func (u *userAccountsTable) GetProfile() account.Profile {
	gender := account.GenderUnspecified
	switch u.Gender {
	case 1:
		gender = account.GenderMale
	case 2:
		gender = account.GenderFemale
	case 3:
		gender = account.GenderOthers
	}

	return account.Profile{
		ID:     u.ID,
		Name:   u.Name,
		Email:  u.Email,
		Gender: gender,
	}
}

func (u *userAccountsTable) GetType() account.Type {
	switch u.Type {
	case 1:
		return account.TypeCustomer
	case 2:
		return account.TypeMerchantCashier
	case 3:
		return account.TypeManagement
	default:
		return account.TypeUnspecified
	}
}

func (u *userAccountsTable) StoreIdentifier() int64 {
	return 0
}

type repository struct {
	db             *sql.DB
	passwordHasher password.Hasher
}

func (r *repository) getUserAccountTableByEmail(ctx context.Context, email string) (*userAccountsTable, error) {
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquiring connection from pool: %w", err)
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			log.Error().Err(err).Msg("closing connection back to pool")
		}
	}()

	var userAccount userAccountsTable
	err = conn.QueryRowContext(
		ctx,
		`SELECT 
				id, 
				name, 
				email, 
				hashed_password, 
				gender, 
				type, 
				email_validated, 
				created_at, 
				created_by, 
				updated_at, 
				updated_by
			FROM 
				coffee.public.user_accounts
			WHERE
				email = $1
			LIMIT 1`,
		email,
	).Scan(
		&userAccount.ID,
		&userAccount.Name,
		&userAccount.Email,
		&userAccount.HashedPassword,
		&userAccount.Gender,
		&userAccount.Type,
		&userAccount.EmailValidated,
		&userAccount.CreatedAt,
		&userAccount.CreatedBy,
		&userAccount.UpdatedAt,
		&userAccount.UpdatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}

		return nil, fmt.Errorf("getting user account by email: %w", err)
	}

	return &userAccount, nil
}

func (r *repository) ValidatePassword(ctx context.Context, account2 account.Account, plainPassword string) (bool, error) {
	if account2 == nil {
		return false, nil
	}

	userAccountTable, err := r.getUserAccountTableByEmail(ctx, account2.GetProfile().Email)
	if err != nil {
		return false, fmt.Errorf("acquiring user account table by email: %w", err)
	}

	ok, err := r.passwordHasher.Verify(ctx, plainPassword, userAccountTable.HashedPassword)
	if err != nil {
		return false, fmt.Errorf("verifying password: %w", err)
	}

	return ok, nil
}

func (r *repository) GetByEmail(ctx context.Context, email string) (account.Account, error) {
	if email == "" {
		return nil, ErrNotFound
	}

	return r.getUserAccountTableByEmail(ctx, email)
}

func (r *repository) Insert(ctx context.Context, rawAccount RawAccount) error {
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquiring connection from pool: %w", err)
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			log.Error().Err(err).Msg("closing connection back to pool")
		}
	}()

	tx, err := conn.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
		ReadOnly:  false,
	})
	if err != nil {
		return fmt.Errorf("creating transaction: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	return nil
}

func (r *repository) DeleteByEmail(ctx context.Context, email string) error {
	// TODO implement me
	panic("implement me")
}

func NewRepository(db *sql.DB, passwordHasher password.Hasher) (AccountStore, error) {
	if db == nil {
		return nil, fmt.Errorf("db is nil")
	}
	if passwordHasher == nil {
		return nil, fmt.Errorf("passwordHasher is nil")
	}

	return &repository{db: db, passwordHasher: passwordHasher}, nil
}
