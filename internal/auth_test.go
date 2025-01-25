package auth

import (
	"fmt"
	"math"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestHashPassword_EmptyString(t *testing.T) {
	_, err := HashPassword("")
	if err == nil {
		t.Error("expected an error when hashing an empty string, got nil")
	}
}

func TestHashPassword_WithSpecialCharacters(t *testing.T) {
	password := "P@ssw0rd!#%"
	hashedPassword, err := HashPassword(password)
	if err != nil {
		t.Errorf("unexpected error when hashing password with special characters: %v", err)
	}

	if hashedPassword == "" {
		t.Error("expected a hashed password, got an empty string")
	}
}

func TestHashPassword_DifferentHashesForSamePassword(t *testing.T) {
	password := "consistentPassword"
	hashedPassword1, err1 := HashPassword(password)
	if err1 != nil {
		t.Errorf("unexpected error when hashing password: %v", err1)
	}

	hashedPassword2, err2 := HashPassword(password)
	if err2 != nil {
		t.Errorf("unexpected error when hashing password: %v", err2)
	}

	if hashedPassword1 == hashedPassword2 {
		t.Error("expected different hashes for the same password on multiple calls, got the same hash")
	}
}

func TestComparePassword_IncorrectPassword(t *testing.T) {
	correctPassword := "correctPassword123"
	incorrectPassword := "wrongPassword456"

	hashedPassword, err := HashPassword(correctPassword)
	if err != nil {
		t.Fatalf("unexpected error when hashing password: %v", err)
	}

	err = ComparePassword(hashedPassword, incorrectPassword)
	if err == nil {
		t.Error("expected an error when comparing an incorrect password with a correct hash, got nil")
	}
}

func TestComparePassword_CorrectPassword(t *testing.T) {
	password := "correctPassword123"

	hashedPassword, err := HashPassword(password)
	if err != nil {
		t.Fatalf("unexpected error when hashing password: %v", err)
	}

	err = ComparePassword(hashedPassword, password)
	if err != nil {
		t.Error("expected nil when comparing a correct password with its correct hash, got an error")
	}
}

func TestComparePassword_EmptyHash(t *testing.T) {
	password := "somePassword"

	err := ComparePassword("", password)
	if err == nil {
		t.Error("expected an error when comparing a password with an empty hash, got nil")
	}
}

func TestComparePassword_InvalidHashFormat(t *testing.T) {
	password := "validPassword"
	invalidHash := "invalidHashFormat"

	err := ComparePassword(invalidHash, password)
	if err == nil {
		t.Error("expected an error when comparing a password with an invalid hash format, got nil")
	}
}

func TestMakeJWT_ValidToken(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "testSecret"
	expiresIn := time.Hour

	os.Setenv("JWT_SECRET", tokenSecret)
	defer os.Unsetenv("JWT_SECRET")

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("unexpected error when creating JWT: %v", err)
	}

	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(tokenSecret), nil
	})

	if err != nil {
		t.Fatalf("error parsing JWT token: %v", err)
	}

	if !parsedToken.Valid {
		t.Error("expected a valid token, got an invalid token")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("failed to extract claims from token")
	}

	if claims["sub"] != userID.String() {
		t.Errorf("expected subject claim to be %s, got %s", userID.String(), claims["sub"])
	}

	if claims["iss"] != "chirpy" {
		t.Errorf("expected issuer claim to be 'chirpy', got %s", claims["iss"])
	}

	issuedAt, ok := claims["iat"].(float64)
	if !ok {
		t.Fatal("failed to extract issued at claim")
	}
	if time.Now().UTC().Sub(time.Unix(int64(issuedAt), 0)) > time.Second {
		t.Error("issued at time is not within the expected range")
	}

	expiresAt, ok := claims["exp"].(float64)
	if !ok {
		t.Fatal("failed to extract expiration claim")
	}
	expectedExpiration := time.Now().UTC().Add(expiresIn)
	if math.Abs(expectedExpiration.Sub(time.Unix(int64(expiresAt), 0)).Seconds()) > 1 {
		t.Error("expiration time is not within the expected range")
	}
}

func TestValidateJWT_InvalidTokenFormat(t *testing.T) {
	invalidToken := "invalidTokenFormat"
	tokenSecret := "testSecret"

	_, err := ValidateJWT(invalidToken, tokenSecret)
	if err == nil {
		t.Error("expected an error when parsing an invalid token format, got nil")
	}
}

func TestValidateJWT_InvalidUUIDSubject(t *testing.T) {
	invalidUUIDToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject: "not-a-valid-uuid",
	})
	tokenSecret := "testSecret"
	tokenString, err := invalidUUIDToken.SignedString([]byte(tokenSecret))
	if err != nil {
		t.Fatalf("unexpected error when signing token: %v", err)
	}

	_, err = ValidateJWT(tokenString, tokenSecret)
	if err == nil || err.Error() != "invalid user ID in token" {
		t.Errorf("expected 'invalid user ID in token' error, got %v", err)
	}
}

func TestValidateJWT_MissingClaims(t *testing.T) {
	// Create a token with missing claims
	token := jwt.New(jwt.SigningMethodHS256)
	tokenSecret := "testSecret"
	tokenString, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		t.Fatalf("unexpected error when signing token: %v", err)
	}

	// Validate the token
	_, err = ValidateJWT(tokenString, tokenSecret)
	if err == nil {
		t.Error("expected an error when validating a token with missing claims, got nil")
	}
}

func TestValidateJWT_ValidToken(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "testSecret"
	expiresIn := time.Hour

	// Create a JWT token with valid claims
	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("unexpected error when creating JWT: %v", err)
	}

	// Validate the token
	parsedUserID, err := ValidateJWT(token, tokenSecret)
	if err != nil {
		t.Fatalf("unexpected error when validating JWT: %v", err)
	}

	// Check if the parsed user ID matches the original user ID
	if parsedUserID != userID {
		t.Errorf("expected user ID %s, got %s", userID, parsedUserID)
	}
}

func TestGetBearerTokenFromHeader_EmptyAuthorizationHeader(t *testing.T) {
	header := http.Header{}
	_, err := GetBearerTokenFromHeader(header)
	if err == nil || err.Error() != "missing Authorization header" {
		t.Errorf("expected 'missing Authorization header' error, got %v", err)
	}
}

func TestGetBearerTokenFromHeader_BearerWithoutToken(t *testing.T) {
	header := http.Header{}
	header.Set("Authorization", "Bearer")

	_, err := GetBearerTokenFromHeader(header)
	if err == nil || err.Error() != "invalid Authorization header" {
		t.Errorf("expected 'invalid Authorization header' error, got %v", err)
	}
}

func TestGetBearerTokenFromHeader_MoreThanTwoParts(t *testing.T) {
	header := http.Header{}
	header.Set("Authorization", "Bearer token extraPart")

	_, err := GetBearerTokenFromHeader(header)
	if err == nil || err.Error() != "invalid Authorization header" {
		t.Errorf("expected 'invalid Authorization header' error, got %v", err)
	}
}

func TestMakeRefreshToken_NonEmptyString(t *testing.T) {
	token, err := MakeRefreshToken()
	if err != nil {
		t.Fatalf("unexpected error when generating refresh token: %v", err)
	}

	if token == "" {
		t.Error("expected a non-empty string for refresh token, got an empty string")
	}
}

func TestMakeRefreshToken_Length(t *testing.T) {
	token, err := MakeRefreshToken()
	if err != nil {
		t.Fatalf("unexpected error when generating refresh token: %v", err)
	}

	if len(token) != 64 {
		t.Errorf("expected token length to be 64, got %d", len(token))
	}
}
