package registration

import (
	"context"
	"database/sql"
	"fmt"
)

type Repository struct {
	db *sql.DB
}

func NewRegistrationRepository(db *sql.DB) (*Repository, error) {
	if db == nil {
		return nil, fmt.Errorf("db is nil")
	}

	return &Repository{db: db}, nil
}

func (r *Repository) Register(ctx context.Context) error {
	return nil
}
