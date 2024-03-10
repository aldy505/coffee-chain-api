package sessionstore

import (
	"context"
	"fmt"
	"sync"
	"time"

	"coffee-chain-api/account"
)

type memorySessionStore struct {
	m *sync.Map
}

func (m *memorySessionStore) Remove(ctx context.Context, token string) error {
	m.m.Delete(token)
	return nil
}

func (m *memorySessionStore) Set(ctx context.Context, session account.Account, token string, expiry time.Time) error {
	m.m.Store(token, session)
	go func(key string, duration time.Duration) {
		time.Sleep(duration)
		m.m.Delete(key)
	}(token, expiry.Sub(time.Now()))
	return nil
}

func (m *memorySessionStore) Get(ctx context.Context, token string) (session account.Account, err error) {
	if token == "" {
		return nil, ErrEmptyToken
	}

	value, ok := m.m.Load(token)
	if !ok {
		return nil, ErrSessionNotExists
	}

	session, ok = value.(account.Account)
	if !ok {
		return nil, fmt.Errorf("unable to assert value as account.Account")
	}

	return session, nil
}

// NewMemorySessionStore implements SessionStore that saves the data in-memory, as the function name states.
// This is only feasible for low traffic, because it spawns many goroutine. For higher traffic, please use
// other SessionStore implementation that uses Redis or anything better.
func NewMemorySessionStore() (SessionStore, error) {
	return &memorySessionStore{
		m: &sync.Map{},
	}, nil
}
