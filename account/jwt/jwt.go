package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type AuthJwt struct {
	accessPrivateKey  ed25519.PrivateKey
	accessPublicKey   ed25519.PublicKey
	refreshPrivateKey ed25519.PrivateKey
	refreshPublicKey  ed25519.PublicKey
	issuer            string
	subject           string
	audience          string
}

func NewJwt(accessPrivateKey []byte, accessPublicKey []byte, refreshPrivateKey []byte, refreshPublicKey []byte, issuer string, subject string, audience string) *AuthJwt {
	return &AuthJwt{
		accessPrivateKey:  accessPrivateKey,
		accessPublicKey:   accessPublicKey,
		refreshPrivateKey: refreshPrivateKey,
		refreshPublicKey:  refreshPublicKey,
		issuer:            issuer,
		subject:           subject,
		audience:          audience,
	}
}

func (j *AuthJwt) Sign(userId int64) (accessToken string, refreshToken string, err error) {
	accessRandId := make([]byte, 32)
	_, _ = rand.Read(accessRandId)

	accessClaims := jwt.MapClaims{
		"iss": j.issuer,
		"sub": j.subject,
		"aud": j.audience,
		"exp": time.Now().Add(time.Hour * 1).Unix(),
		"nbf": time.Now().Unix(),
		"iat": time.Now().Unix(),
		"jti": string(accessRandId),
		"uid": userId,
	}

	accessToken, err = jwt.NewWithClaims(jwt.SigningMethodEdDSA, accessClaims).SignedString(j.accessPrivateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign access token: %w", err)
	}

	refreshRandId := make([]byte, 32)
	_, _ = rand.Read(refreshRandId)

	refreshClaims := jwt.MapClaims{
		"iss": j.issuer,
		"sub": j.subject,
		"aud": j.audience,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
		"nbf": time.Now().Add(time.Minute * 59).Unix(),
		"iat": time.Now().Unix(),
		"jti": string(refreshRandId),
		"uid": userId,
	}

	refreshToken, err = jwt.NewWithClaims(jwt.SigningMethodEdDSA, refreshClaims).SignedString(j.refreshPrivateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

var ErrInvalidSigningMethod = errors.New("invalid signing method")
var ErrExpired = errors.New("token expired")
var ErrInvalid = errors.New("token invalid")
var ErrClaims = errors.New("token claims invalid")

func (j *AuthJwt) VerifyAccessToken(token string) (userId int64, err error) {
	if token == "" {
		return 0, ErrInvalid
	}

	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		_, ok := t.Method.(*jwt.SigningMethodEd25519)
		if !ok {
			return nil, ErrInvalidSigningMethod
		}
		return j.accessPublicKey, nil
	})
	if err != nil {
		if parsedToken != nil && !parsedToken.Valid {
			// Check if the error is a type of jwt.ValidationError
			validationError, ok := err.(*jwt.ValidationError)
			if ok {
				if validationError.Errors&jwt.ValidationErrorExpired != 0 {
					return 0, ErrExpired
				}

				if validationError.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
					return 0, ErrInvalid
				}

				if validationError.Errors&jwt.ValidationErrorClaimsInvalid != 0 {
					return 0, ErrClaims
				}

				return 0, fmt.Errorf("failed to parse access token: %w", err)
			}

			return 0, fmt.Errorf("non-validation error during parsing token: %w", err)
		}

		return 0, fmt.Errorf("token is valid or parsedToken is not nil: %w", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return 0, ErrClaims
	}

	if !claims.VerifyAudience(j.audience, true) {
		return 0, ErrInvalid
	}

	if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
		return 0, ErrExpired
	}

	if !claims.VerifyIssuer(j.issuer, true) {
		return 0, ErrInvalid
	}

	if !claims.VerifyNotBefore(time.Now().Unix(), true) {
		return 0, ErrInvalid
	}

	jwtId, ok := claims["jti"].(string)
	if !ok {
		return 0, ErrClaims
	}

	if jwtId == "" {
		return 0, ErrClaims
	}

	userIdF, ok := claims["uid"].(float64)
	if !ok {
		return 0, ErrClaims
	}

	return int64(userIdF), nil
}

func (j *AuthJwt) VerifyRefreshToken(token string) (userId int64, err error) {
	if token == "" {
		return 0, ErrInvalid
	}

	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		_, ok := t.Method.(*jwt.SigningMethodEd25519)
		if !ok {
			return nil, ErrInvalidSigningMethod
		}
		return j.refreshPublicKey, nil
	})
	if err != nil {
		if parsedToken != nil && !parsedToken.Valid {
			// Check if the error is a type of jwt.ValidationError
			validationError, ok := err.(*jwt.ValidationError)
			if ok {
				if validationError.Errors&jwt.ValidationErrorExpired != 0 {
					return 0, ErrExpired
				}

				if validationError.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
					return 0, ErrInvalid
				}

				if validationError.Errors&jwt.ValidationErrorClaimsInvalid != 0 {
					return 0, ErrClaims
				}

				if validationError.Errors&jwt.ValidationErrorNotValidYet != 0 {
					return 0, ErrInvalid
				}

				return 0, fmt.Errorf("failed to parse access token: %w", err)
			}

			return 0, fmt.Errorf("non-validation error during parsing token: %w", err)
		}

		return 0, fmt.Errorf("token is valid or parsedToken is not nil: %w", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return 0, ErrClaims
	}

	if !claims.VerifyAudience(j.audience, true) {
		return 0, ErrInvalid
	}

	if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
		return 0, ErrExpired
	}

	if !claims.VerifyIssuer(j.issuer, true) {
		return 0, ErrInvalid
	}

	if !claims.VerifyNotBefore(time.Now().Unix(), true) {
		return 0, ErrInvalid
	}

	jwtId, ok := claims["jti"].(string)
	if !ok {
		return 0, ErrClaims
	}

	if jwtId == "" {
		return 0, ErrClaims
	}

	userId, ok = claims["uid"].(int64)
	if !ok {
		return 0, ErrClaims
	}

	return userId, nil
}
