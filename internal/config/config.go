package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type Config struct {
	DataDir         string
	KeyFile         string
	SessionTTL      time.Duration
	LockoutDuration time.Duration
	MaxAttempts     int
	Issuer          string
}

func Load() (Config, error) { return Parse(os.LookupEnv) }

func Parse(lookup func(string) (string, bool)) (Config, error) {
	get := func(key, fallback string) string {
		if value, ok := lookup(key); ok {
			return value
		}
		return fallback
	}
	c := Config{DataDir: get("APP_DATA_DIR", "./data"), Issuer: get("APP_ISSUER", "CLI Login")}
	if strings.TrimSpace(c.DataDir) == "" {
		return c, fmt.Errorf("APP_DATA_DIR cannot be empty")
	}
	c.KeyFile = get("APP_KEY_FILE", filepath.Join(c.DataDir, "master.key"))
	if strings.TrimSpace(c.KeyFile) == "" {
		return c, fmt.Errorf("APP_KEY_FILE cannot be empty")
	}
	if !utf8.ValidString(c.Issuer) || len(c.Issuer) == 0 || len(c.Issuer) > 64 || strings.Contains(c.Issuer, ":") || strings.IndexFunc(c.Issuer, unicode.IsControl) >= 0 || strings.TrimSpace(c.Issuer) != c.Issuer {
		return c, fmt.Errorf("APP_ISSUER must be 1–64 bytes without colons, control characters or surrounding whitespace")
	}
	var err error
	c.SessionTTL, err = time.ParseDuration(get("APP_SESSION_TTL", "30m"))
	if err != nil || c.SessionTTL < time.Second || c.SessionTTL > 24*time.Hour {
		return c, fmt.Errorf("APP_SESSION_TTL must be a duration between 1s and 24h")
	}
	c.LockoutDuration, err = time.ParseDuration(get("APP_LOCKOUT_DURATION", "15m"))
	if err != nil || c.LockoutDuration < time.Second || c.LockoutDuration > 24*time.Hour {
		return c, fmt.Errorf("APP_LOCKOUT_DURATION must be a duration between 1s and 24h")
	}
	c.MaxAttempts, err = strconv.Atoi(get("APP_MAX_ATTEMPTS", "5"))
	if err != nil || c.MaxAttempts < 1 || c.MaxAttempts > 20 {
		return c, fmt.Errorf("APP_MAX_ATTEMPTS must be an integer between 1 and 20")
	}
	return c, nil
}
