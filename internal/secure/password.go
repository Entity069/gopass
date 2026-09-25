package secure

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	passwordMemory   = 64 * 1024 // 64 MB per operation
	passwordTime     = 3
	passwordThreads  = 2
	MaxPasswordBytes = 1024
)

var ErrPasswordPolicy = errors.New("password must contain 8–1024 characters (at most 1024 bytes), with no control characters, and cannot be only whitespace")

// passwords uses argon2id with a fresh 128-bit salt and a 256-bit output, never trimmed or truncated

type Passwords struct{}

func ValidatePassword(password []byte) error {
	if !utf8.Valid(password) || len(password) > MaxPasswordBytes || utf8.RuneCount(password) < 8 || strings.TrimSpace(string(password)) == "" || strings.IndexFunc(string(password), unicode.IsControl) >= 0 {
		return ErrPasswordPolicy
	}
	return nil
}

func (Passwords) Hash(password []byte) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey(password, salt, passwordTime, passwordMemory, passwordThreads, 32)
	defer clear(key)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", passwordMemory, passwordTime, passwordThreads, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func (Passwords) Verify(encoded string, password []byte) bool {
	if len(password) > MaxPasswordBytes || len(encoded) > 256 {
		return false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return false
	}
	values := make([]uint64, 3)
	for i, prefix := range []string{"m=", "t=", "p="} {
		if !strings.HasPrefix(params[i], prefix) {
			return false
		}
		v, err := strconv.ParseUint(strings.TrimPrefix(params[i], prefix), 10, 32)
		if err != nil {
			return false
		}
		values[i] = v
	}

	if values[0] != passwordMemory || values[1] != passwordTime || values[2] != passwordThreads {
		return false
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) != 16 {
		return false
	}
	expected, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(expected) != 32 {
		return false
	}
	actual := argon2.IDKey(password, salt, passwordTime, passwordMemory, passwordThreads, 32)
	defer clear(actual)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}
