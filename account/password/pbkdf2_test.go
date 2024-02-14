package password_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"coffee-chain-api/account/password"
)

func TestPbdkf2Hasher_Hash(t *testing.T) {
	hasher, err := password.NewPbdkf2PasswordHasher(password.Pbdkf2Config{
		Rounds:   0,
		KeyLen:   0,
		HashFunc: 0,
		SaltLen:  0,
	})
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

func TestPbdkf2Hasher_Verify(t *testing.T) {
	hasher, err := password.NewPbdkf2PasswordHasher(password.Pbdkf2Config{
		Rounds:   0,
		KeyLen:   0,
		HashFunc: 0,
		SaltLen:  0,
	})
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

func TestPbdkf2Hasher_CustomHashFunc(t *testing.T) {
	ctx := context.Background()

	t.Run("SHA1", func(t *testing.T) {
		hasher, err := password.NewPbdkf2PasswordHasher(password.Pbdkf2Config{
			HashFunc: password.SHA1,
		})
		if err != nil {
			t.Fatalf("creating hasher: %s", err.Error())
		}

		hash, err := hasher.Hash(ctx, "password123")
		if err != nil {
			t.Error(err)
		}

		verify, err := hasher.Verify(ctx, "password123", hash)
		if err != nil {
			t.Error(err)
		}
		if !verify {
			t.Error("verify function returned false")
		}
	})

	t.Run("SHA256", func(t *testing.T) {
		hasher, err := password.NewPbdkf2PasswordHasher(password.Pbdkf2Config{
			HashFunc: password.SHA256,
		})
		if err != nil {
			t.Fatalf("creating hasher: %s", err.Error())
		}

		hash, err := hasher.Hash(ctx, "password123")
		if err != nil {
			t.Error(err)
		}

		verify, err := hasher.Verify(ctx, "password123", hash)
		if err != nil {
			t.Error(err)
		}
		if !verify {
			t.Error("verify function returned false")
		}
	})

	t.Run("SHA224", func(t *testing.T) {
		hasher, err := password.NewPbdkf2PasswordHasher(password.Pbdkf2Config{
			HashFunc: password.SHA224,
		})
		if err != nil {
			t.Fatalf("creating hasher: %s", err.Error())
		}

		hash, err := hasher.Hash(ctx, "password123")
		if err != nil {
			t.Error(err)
		}

		verify, err := hasher.Verify(ctx, "password123", hash)
		if err != nil {
			t.Error(err)
		}
		if !verify {
			t.Error("verify function returned false")
		}
	})

	t.Run("SHA512", func(t *testing.T) {
		hasher, err := password.NewPbdkf2PasswordHasher(password.Pbdkf2Config{
			HashFunc: password.SHA512,
		})
		if err != nil {
			t.Fatalf("creating hasher: %s", err.Error())
		}

		hash, err := hasher.Hash(ctx, "password123")
		if err != nil {
			t.Error(err)
		}

		verify, err := hasher.Verify(ctx, "password123", hash)
		if err != nil {
			t.Error(err)
		}
		if !verify {
			t.Error("verify function returned false")
		}
	})

	t.Run("SHA384", func(t *testing.T) {
		hasher, err := password.NewPbdkf2PasswordHasher(password.Pbdkf2Config{
			HashFunc: password.SHA384,
		})
		if err != nil {
			t.Fatalf("creating hasher: %s", err.Error())
		}

		hash, err := hasher.Hash(ctx, "password123")
		if err != nil {
			t.Error(err)
		}

		verify, err := hasher.Verify(ctx, "password123", hash)
		if err != nil {
			t.Error(err)
		}
		if !verify {
			t.Error("verify function returned false")
		}
	})

	t.Run("MD5", func(t *testing.T) {
		hasher, err := password.NewPbdkf2PasswordHasher(password.Pbdkf2Config{
			HashFunc: password.MD5,
		})
		if err != nil {
			t.Fatalf("creating hasher: %s", err.Error())
		}

		hash, err := hasher.Hash(ctx, "password123")
		if err != nil {
			t.Error(err)
		}

		verify, err := hasher.Verify(ctx, "password123", hash)
		if err != nil {
			t.Error(err)
		}
		if !verify {
			t.Error("verify function returned false")
		}
	})
}

func TestPbdkf2Hasher_Error(t *testing.T) {
	hasher, err := password.NewPbdkf2PasswordHasher(password.Pbdkf2Config{
		Rounds:   0,
		KeyLen:   0,
		HashFunc: 0,
		SaltLen:  0,
	})
	if err != nil {
		t.Fatalf("initializing argon2 hasher: %s", err.Error())
	}

	ctx := context.Background()

	t.Run("should return error", func(t *testing.T) {
		hashString := "$pkt$v=0$i=32$invalidSalt$invalidHash"
		_, err := hasher.Verify(ctx, "something", hashString)
		if !errors.Is(err, password.ErrUnexpectedHasherInstance) {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should fail parsing int", func(t *testing.T) {
		hashString := "$pbkdf2sha256$v=0$i=a$d172c14e9955bf4e4c01422f2af10d4f$ad21bd7d8568ce800754aafb6630e7e909006c425489778f8016d3471951d3cc"
		_, err := hasher.Verify(ctx, "something", hashString)
		if err == nil {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should fail parsing hex - hash", func(t *testing.T) {
		hashString := "$pbkdf2sha256$v=0$i=4096$d172c14e9955bf4e4c01422f2af10d4f$invalidHash"
		_, err := hasher.Verify(ctx, "something", hashString)
		if err == nil {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should fail parsing hex - salt", func(t *testing.T) {
		hashString := "$pbkdf2sha256$v=0$i=4096$invalidSalt$ad21bd7d8568ce800754aafb6630e7e909006c425489778f8016d3471951d3cc"
		_, err := hasher.Verify(ctx, "something", hashString)
		if err == nil {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("not supported hash function", func(t *testing.T) {
		hashString := "$pbkdf2asdf$v=0$i=4096$d172c14e9955bf4e4c01422f2af10d4f$ad21bd7d8568ce800754aafb6630e7e909006c425489778f8016d3471951d3cc"
		_, err := hasher.Verify(ctx, "something", hashString)
		if !errors.Is(err, password.ErrUnexpectedHasherInstance) {
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
