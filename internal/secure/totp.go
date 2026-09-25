package secure

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func NewTOTP(issuer, username string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: username, SecretSize: 20, Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
}

// MatchTOTP validates 6-digit codes within 30s and returns the counter for atomic replay protection
func MatchTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	if len(code) != 6 || now.Unix() < 0 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	matched := int64(-1)
	for _, offset := range []int64{0, -1, 1} {
		step := now.Unix()/30 + offset
		if step < 0 {
			continue
		}
		expected, err := totp.GenerateCode(secret, time.Unix(step*30, 0))
		if err == nil && subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 && step > matched {
			matched = step
		}
	}
	return matched, matched > lastStep && matched >= 0
}

func NewToken() (string, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(token[:]), nil
}

func TokenHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func ValidToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}
