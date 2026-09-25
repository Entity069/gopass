package secure

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/argon2"
)

func TestPasswordPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		valid       bool
	}{
		{"empty", "", false}, {"short", "se7en!!", false}, {"minimum", strings.Repeat("a", 8), true},
		{"spaces", strings.Repeat(" ", 8), false}, {"passphrase", "a long memorable passphrase", true},
		{"unicode too short", strings.Repeat("é", 7), false}, {"unicode valid", strings.Repeat("é", 8), true},
		{"max bytes", strings.Repeat("a", 1024), true}, {"too many bytes", strings.Repeat("a", 1025), false},
		{"unicode byte limit", strings.Repeat("é", 513), false}, {"invalid utf8", "long password test\xff", false},
		{"nul", "long password test\x00", false}, {"newline", "long password test\n", false},
		{"escape", "long password test\x1b", false}, {"surrounding spaces preserved", "  long password here  ", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if (ValidatePassword([]byte(tc.value)) == nil) != tc.valid {
				t.Fatalf("valid=%v", tc.valid)
			}
		})
	}
}

func TestPasswords(t *testing.T) {
	p := Passwords{}
	password := []byte("  correct horse battery staple  ")
	hash, err := p.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	other, err := p.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	if hash == other || strings.Contains(hash, string(password)) || !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatal("hash policy or salt uniqueness failed")
	}
	if !p.Verify(hash, password) || p.Verify(hash, []byte("incorrect password")) || p.Verify(hash, bytes.TrimSpace(password)) {
		t.Fatal("password verification or whitespace preservation failed")
	}
	parts := strings.Split(hash, "$")
	salt, _ := base64.RawStdEncoding.DecodeString(parts[4])
	expected := argon2.IDKey(password, salt, 3, 64*1024, 2, 32)
	if base64.RawStdEncoding.EncodeToString(expected) != parts[5] {
		t.Fatal("PHC encoding does not match Argon2id")
	}
	if _, err := p.Hash([]byte("short")); err == nil {
		t.Fatal("weak password accepted")
	}
	for _, corrupt := range []string{
		"", "$argon2i$v=19$m=65536,t=3,p=2$x$y", strings.Replace(hash, "v=19", "v=16", 1),
		strings.Replace(hash, "m=65536", "m=4294967295", 1), strings.Replace(hash, "t=3", "t=0", 1),
		strings.Replace(hash, "p=2", "p=0", 1), strings.Replace(hash, "m=65536", "m=-1", 1),
		strings.Replace(hash, "m=65536", "m=oops", 1), strings.Replace(hash, "p=2", "q=2", 1),
		strings.Replace(hash, "p=2", "p=2,extra=1", 1), hash + "$extra", hash[:len(hash)-1],
		strings.Replace(hash, parts[4], "!!!", 1), strings.Replace(hash, parts[5], "!!!", 1), strings.Repeat("$", 257),
	} {
		if p.Verify(corrupt, password) {
			t.Fatal("corrupt hash accepted")
		}
	}
	if p.Verify(hash, bytes.Repeat([]byte("a"), 1025)) {
		t.Fatal("oversized password accepted")
	}
}

func TestVault(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	v, err := NewVault(key)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("SECRET-TOTP-SEED")
	a, b := v.Seal(secret, "alice"), v.Seal(secret, "alice")
	if bytes.Equal(a, b) || bytes.Contains(a, secret) {
		t.Fatal("ciphertext not randomized or secret exposed")
	}
	plain, err := v.Open(a, "alice")
	if err != nil || !bytes.Equal(plain, secret) {
		t.Fatal("round trip failed", err)
	}
	if _, err := v.Open(a, "bob"); err == nil {
		t.Fatal("cross-user substitution accepted")
	}
	for _, input := range [][]byte{nil, {}, {1}, a[:len(a)-1], append([]byte{a[0] ^ 1}, a[1:]...)} {
		if _, err := v.Open(input, "alice"); err == nil {
			t.Fatal("tamper/truncation accepted")
		}
	}
	other, _ := NewVault(bytes.Repeat([]byte{8}, 32))
	if _, err := other.Open(a, "alice"); err == nil {
		t.Fatal("wrong key accepted")
	}
	if other.ID() == v.ID() {
		t.Fatal("key fingerprints collided")
	}
	for _, n := range []int{0, 16, 24, 31, 33} {
		if _, err := NewVault(make([]byte, n)); err == nil {
			t.Fatal("invalid AES-256 key size accepted")
		}
	}
}

func TestKeyPersistenceAndPermissions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "master.key")
	if _, err := LoadKey(path, false); err == nil {
		t.Fatal("missing key recreated for existing database")
	}
	first, err := LoadKey(path, true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadKey(path, false)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("key did not persist", err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 || info.Size() != 32 {
		t.Fatal("key permissions/size incorrect")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path, true); err == nil {
		t.Fatal("public key file accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(link, true); err == nil {
		t.Fatal("symlink accepted")
	}
	if _, err := LoadKey(dir, false); err == nil {
		t.Fatal("directory key accepted")
	}
	bad := filepath.Join(dir, "short")
	if err := os.WriteFile(bad, []byte("short"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(bad, true); err == nil {
		t.Fatal("malformed existing key overwritten")
	}
}

func TestConcurrentKeyCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "master.key")
	var wg sync.WaitGroup
	keys := make(chan []byte, 12)
	for i := 0; i < 12; i++ {
		wg.Go(func() {
			key, err := LoadKey(path, true)
			if err != nil {
				t.Error(err)
				return
			}
			keys <- key
		})
	}
	wg.Wait()
	close(keys)
	var first []byte
	for key := range keys {
		if first == nil {
			first = key
		}
		if !bytes.Equal(first, key) {
			t.Fatal("concurrent key creation diverged")
		}
	}
}

func TestPrivateDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := PrivateDir(dir); err == nil {
		t.Fatal("public directory accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := PrivateDir(link); err == nil {
		t.Fatal("symlink directory accepted")
	}
}

func TestTOTPVectorsAndWindow(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, tc := range []struct {
		unix int64
		code string
	}{
		{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"},
	} {
		step, valid := MatchTOTP(secret, tc.code, time.Unix(tc.unix, 0), -1)
		if !valid || step != tc.unix/30 {
			t.Fatalf("RFC vector %d failed", tc.unix)
		}
		if _, valid := MatchTOTP(secret, tc.code, time.Unix(tc.unix, 0), step); valid {
			t.Fatal("code replay accepted")
		}
	}
	now := time.Unix(1700000010, 0)
	for _, offset := range []int64{-2, -1, 0, 1, 2} {
		code, _ := totp.GenerateCode(secret, now.Add(time.Duration(offset)*30*time.Second))
		_, valid := MatchTOTP(secret, code, now, -1)
		if valid != (offset >= -1 && offset <= 1) {
			t.Fatalf("wrong skew handling: %d", offset)
		}
	}
	for _, code := range []string{"", "12345", "1234567", "abcdef", "１２３４５６", " 12345", "12345\n"} {
		if _, valid := MatchTOTP(secret, code, now, -1); valid {
			t.Fatal("invalid code format accepted")
		}
	}
	if _, valid := MatchTOTP("!bad!", "123456", now, -1); valid {
		t.Fatal("invalid secret accepted")
	}
	if _, valid := MatchTOTP(secret, "123456", time.Unix(-1, 0), -1); valid {
		t.Fatal("negative time accepted")
	}
	code, _ := totp.GenerateCode(secret, time.Unix(0, 0))
	if _, valid := MatchTOTP(secret, code, time.Unix(0, 0), -1); !valid {
		t.Fatal("epoch code rejected")
	}
}

func TestTOTPGenerationAndTokens(t *testing.T) {
	a, err := NewTOTP("CLI Login", "alice")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTOTP("CLI Login", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if a.Secret() == b.Secret() || len(a.Secret()) != 32 || !strings.HasPrefix(a.URL(), "otpauth://totp/") || a.Issuer() != "CLI Login" || a.AccountName() != "alice" {
		t.Fatal("bad provisioning key")
	}
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		token, err := NewToken()
		if err != nil {
			t.Fatal(err)
		}
		if !ValidToken(token) || seen[token] || TokenHash(token) == token || len(TokenHash(token)) != 64 {
			t.Fatal("bad session token")
		}
		seen[token] = true
	}
	for _, token := range []string{"", strings.Repeat("g", 64), strings.Repeat("0", 63), strings.Repeat("0", 65), "' OR 1=1--"} {
		if ValidToken(token) {
			t.Fatal("malformed token accepted")
		}
	}
}

func FuzzVerifyPassword(f *testing.F) {
	f.Add("$argon2id$v=19$m=4294967295,t=3,p=2$bad$bad", "password")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, hash, password string) { (Passwords{}).Verify(hash, []byte(password)) })
}

func FuzzMatchTOTP(f *testing.F) {
	f.Add("JBSWY3DPEHPK3PXP", "123456", int64(1700000000))
	f.Fuzz(func(t *testing.T, secret, code string, unix int64) {
		if len(secret) > 1024 {
			t.Skip()
		}
		MatchTOTP(secret, code, time.Unix(unix, 0), -1)
	})
}
