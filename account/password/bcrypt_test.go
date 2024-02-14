package password_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"coffee-chain-api/account/password"
)

func TestBcryptHasher_Hash(t *testing.T) {
	hasher, err := password.NewBcryptPasswordHasher(10)
	if err != nil {
		t.Fatalf("initializing argon2 hasher: %s", err.Error())
	}

	ctx := context.Background()

	t.Run("should be ok without additional config", func(t *testing.T) {
		hash, err := hasher.Hash(ctx, "password123")
		if err != nil {
			t.Error(err)
		}

		typeof := reflect.TypeOf(hash).Kind()
		if typeof != reflect.String {
			t.Error("returned type is not string")
		}
	})
}

func TestBcryptHasher_Verify(t *testing.T) {
	hasher, err := password.NewBcryptPasswordHasher(10)
	if err != nil {
		t.Fatalf("initializing argon2 hasher: %s", err.Error())
	}

	ctx := context.Background()

	t.Run("verify should return true", func(t *testing.T) {
		hash, err := hasher.Hash(ctx, "password123")
		if err != nil {
			t.Error(err)
		}

		verify, err := hasher.Verify(ctx, "password123", hash)
		if err != nil {
			t.Error(err)
		}

		typeof := reflect.TypeOf(verify).Kind()
		if typeof != reflect.Bool {
			t.Error("returned type is not boolean")
		}

		if !verify {
			t.Error("verify function returned false")
		}
	})

	t.Run("verify should return false", func(t *testing.T) {
		hash, err := hasher.Hash(ctx, "password123")
		if err != nil {
			t.Error(err)
		}

		verify, err := hasher.Verify(ctx, "password321", hash)
		if err != nil {
			t.Error(err)
		}

		typeof := reflect.TypeOf(verify).Kind()
		if typeof != reflect.Bool {
			t.Error("returned type is not boolean")
		}

		if verify {
			t.Error("verify function returned false")
		}
	})
}

func TestBcryptHasher_Error(t *testing.T) {
	hasher, err := password.NewBcryptPasswordHasher(10)
	if err != nil {
		t.Fatalf("initializing argon2 hasher: %s", err.Error())
	}

	ctx := context.Background()

	t.Run("should return error", func(t *testing.T) {
		hashString := "$bct$v=0$r=32$invalidSalt$invalidHash"
		_, err := hasher.Verify(ctx, "something", hashString)
		if !errors.Is(err, password.ErrUnexpectedHasherInstance) {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should fail decoding hex - hash", func(t *testing.T) {
		hashString := "$bcrypt$v=0$r=32$invalidSalt$invalidHash"
		_, err := hasher.Verify(ctx, "something", hashString)
		if err == nil {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should complain of empty function parameters", func(t *testing.T) {
		_, err := hasher.Hash(ctx, "")
		if !errors.Is(err, password.ErrEmptyToken) {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should complain of empty function parameters", func(t *testing.T) {
		_, err := hasher.Verify(ctx, "", "")
		if !errors.Is(err, password.ErrEmptyToken) {
			t.Error("error should have been thrown:", err)
		}
	})
}
