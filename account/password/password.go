package password

import (
	"context"
	"errors"
)

var ErrEmptyToken = errors.New("string token is empty")
var ErrUnexpectedHasherInstance = errors.New("unexpected hasher instance")

type Hasher interface {
	Hash(ctx context.Context, plainPassword string) (string, error)
	Verify(ctx context.Context, plainPassword string, hashedPassword string) (bool, error)
}
