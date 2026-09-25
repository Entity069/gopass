package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func parse(values map[string]string) (Config, error) {
	return Parse(func(key string) (string, bool) { value, ok := values[key]; return value, ok })
}

func TestDefaults(t *testing.T) {
	c, err := parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.DataDir != "./data" || c.KeyFile != filepath.Join("data", "master.key") || c.SessionTTL != 30*time.Minute || c.MaxAttempts != 5 || c.LockoutDuration != 15*time.Minute || c.Issuer != "CLI Login" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, key, value string
		valid            bool
	}{
		{"minimum ttl", "APP_SESSION_TTL", "1s", true}, {"maximum ttl", "APP_SESSION_TTL", "24h", true},
		{"zero ttl", "APP_SESSION_TTL", "0s", false}, {"negative ttl", "APP_SESSION_TTL", "-1m", false},
		{"tiny ttl", "APP_SESSION_TTL", "999ms", false}, {"long ttl", "APP_SESSION_TTL", "24h1s", false},
		{"invalid ttl", "APP_SESSION_TTL", "forever", false}, {"empty ttl", "APP_SESSION_TTL", "", false},
		{"duration overflow", "APP_SESSION_TTL", "999999999999999999h", false},
		{"lockout override", "APP_LOCKOUT_DURATION", "2m", true}, {"zero lockout", "APP_LOCKOUT_DURATION", "0", false},
		{"long lockout", "APP_LOCKOUT_DURATION", "25h", false},
		{"one attempt", "APP_MAX_ATTEMPTS", "1", true}, {"maximum attempts", "APP_MAX_ATTEMPTS", "20", true},
		{"no attempts", "APP_MAX_ATTEMPTS", "0", false}, {"negative attempts", "APP_MAX_ATTEMPTS", "-1", false},
		{"many attempts", "APP_MAX_ATTEMPTS", "21", false}, {"nonnumeric attempts", "APP_MAX_ATTEMPTS", "five", false},
		{"empty directory", "APP_DATA_DIR", " ", false}, {"custom directory", "APP_DATA_DIR", "/tmp/private", true},
		{"empty key", "APP_KEY_FILE", "", false}, {"custom key", "APP_KEY_FILE", "/run/secrets/key", true},
		{"empty issuer", "APP_ISSUER", "", false}, {"colon issuer", "APP_ISSUER", "a:b", false},
		{"control issuer", "APP_ISSUER", "evil\x1b[2J", false}, {"newline issuer", "APP_ISSUER", "a\nb", false},
		{"long issuer", "APP_ISSUER", strings.Repeat("a", 65), false}, {"issuer whitespace", "APP_ISSUER", " a ", false},
		{"unicode issuer", "APP_ISSUER", "सुरक्षित Login", true},
		{"invalid utf8 issuer", "APP_ISSUER", "bad\xff", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(map[string]string{tc.key: tc.value})
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}
