package password_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"coffee-chain-api/account/password"
)

func TestArgon2Hasher_Hash(t *testing.T) {
	hasher, err := password.NewArgonPasswordHasher(password.Argon2Config{})
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

	t.Run("should return two different string", func(t *testing.T) {
		hash1, err := hasher.Hash(ctx, "password123")
		if err != nil {
			t.Error(err)
		}

		hash2, err := hasher.Hash(ctx, "password123")
		if err != nil {
			t.Error(err)
		}

		if hash1 == hash2 {
			t.Error("hash1 and hash2 have the same value")
		}
	})
}

func TestArgon2Hasher_Verify(t *testing.T) {
	hasher, err := password.NewArgonPasswordHasher(password.Argon2Config{})
	if err != nil {
		t.Fatalf("initializing argon2 hasher: %s", err.Error())
	}

	ctx := context.Background()

	t.Run("verify should return true - argon2id", func(t *testing.T) {
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

	t.Run("verify should return true - argon2i", func(t *testing.T) {
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

func TestArgon2Hasher_Error(t *testing.T) {
	hasher, err := password.NewArgonPasswordHasher(password.Argon2Config{})
	if err != nil {
		t.Fatalf("initializing argon2 hasher: %s", err.Error())
	}

	ctx := context.Background()

	t.Run("should return error", func(t *testing.T) {
		hashString := "$argon3$v=2$t=16,m=64,p=32$invalidSalt$invalidHash"
		_, err := hasher.Verify(ctx, "something", hashString)
		if !errors.Is(err, password.ErrUnexpectedHasherInstance) {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should fail parsing int - 1", func(t *testing.T) {
		hashString := "$argon2id$v=2$t=a,m=64,p=32$9336bb54e8f5532cc1f3050262d90b8d2c0cdca01321a8661c5e8da641798199$c9e0d744acafe5ddcb844942a75b86d5c878d3656d4ce17f5c30c3b31a117b41fd9785b1dfa47c79f6f8684acaad7055a964ba99bbc8cf225bfe405bac22d5d2"
		_, err := hasher.Verify(ctx, "something", hashString)
		if err == nil {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should fail parsing int - 2", func(t *testing.T) {
		hashString := "$argon2id$v=2$t=16,m=a,p=32$9336bb54e8f5532cc1f3050262d90b8d2c0cdca01321a8661c5e8da641798199$c9e0d744acafe5ddcb844942a75b86d5c878d3656d4ce17f5c30c3b31a117b41fd9785b1dfa47c79f6f8684acaad7055a964ba99bbc8cf225bfe405bac22d5d2"
		_, err := hasher.Verify(ctx, "something", hashString)
		if err == nil {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should fail parsing int - 3", func(t *testing.T) {
		hashString := "$argon2id$v=2$t=16,m=64,p=a$9336bb54e8f5532cc1f3050262d90b8d2c0cdca01321a8661c5e8da641798199$c9e0d744acafe5ddcb844942a75b86d5c878d3656d4ce17f5c30c3b31a117b41fd9785b1dfa47c79f6f8684acaad7055a964ba99bbc8cf225bfe405bac22d5d2"
		_, err := hasher.Verify(ctx, "something", hashString)
		if err == nil {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should fail decoding hex - salt", func(t *testing.T) {
		hashString := "$argon2id$v=2$t=16,m=64,p=32$invalidSalt$c9e0d744acafe5ddcb844942a75b86d5c878d3656d4ce17f5c30c3b31a117b41fd9785b1dfa47c79f6f8684acaad7055a964ba99bbc8cf225bfe405bac22d5d2"
		_, err := hasher.Verify(ctx, "something", hashString)
		if err == nil {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should fail decoding hex - hash", func(t *testing.T) {
		hashString := "$argon2id$v=2$t=16,m=64,p=32$9336bb54e8f5532cc1f3050262d90b8d2c0cdca01321a8661c5e8da641798199$invalidHash"
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
