package jwt_test

import (
	"crypto/ed25519"
	"errors"
	"log"
	"os"
	"testing"

	"coffee-chain-api/account/jwt"
)

var authJwt *jwt.AuthJwt

func TestMain(m *testing.M) {
	// Generate ed25519 key pairs for access and refresh tokens
	accessPublicKey, accessPrivateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatalf("failed to generate access key pair: %v", err)
	}

	refreshPublicKey, refreshPrivateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatalf("failed to generate refresh key pair: %v", err)
	}

	authJwt = jwt.NewJwt(accessPrivateKey, accessPublicKey, refreshPrivateKey, refreshPublicKey, "kodiiing", "user", "kodiiing")

	exitCode := m.Run()

	os.Exit(exitCode)
}

func TestSign(t *testing.T) {
	accessToken, refreshToken, err := authJwt.Sign(1)
	if err != nil {
		t.Errorf("failed to sign access token: %v", err)
	}

	if accessToken == "" {
		t.Error("access token is empty")
	}
	if refreshToken == "" {
		t.Error("refresh token is empty")
	}
}

func TestVerify(t *testing.T) {
	accessToken, refreshToken, err := authJwt.Sign(1)
	if err != nil {
		t.Errorf("failed to sign access token: %v", err)
	}

	if accessToken == "" {
		t.Error("access token is empty")
	}
	if refreshToken == "" {
		t.Error("refresh token is empty")
	}

	accessId, err := authJwt.VerifyAccessToken(accessToken)
	if err != nil {
		t.Errorf("failed to verify access token: %v", err)
	}

	if accessId != 1 {
		t.Errorf("access id is not 1: %v", accessId)
	}

	refreshId, err := authJwt.VerifyRefreshToken(refreshToken)
	if err == nil {
		t.Errorf("refresh token is valid: %v", refreshId)
	}

	if !errors.Is(err, jwt.ErrInvalid) {
		t.Errorf("error is not ErrInvalid: %v", err)
	}
}

func TestVerifyEmpty(t *testing.T) {
	accessId, err := authJwt.VerifyAccessToken("")
	if err == nil {
		t.Errorf("access token is valid: %v", accessId)
	}

	if !errors.Is(err, jwt.ErrInvalid) {
		t.Errorf("error is not ErrInvalid: %v", err)
	}

	refreshId, err := authJwt.VerifyRefreshToken("")
	if err == nil {
		t.Errorf("refresh token is valid: %v", refreshId)
	}

	if !errors.Is(err, jwt.ErrInvalid) {
		t.Errorf("error is not ErrInvalid: %v", err)
	}
}
