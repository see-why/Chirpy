package auth

import "testing"

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
