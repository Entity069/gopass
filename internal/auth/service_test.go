package auth

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/osto-assignment/cli-login/internal/config"
	"github.com/osto-assignment/cli-login/internal/secure"
	"github.com/osto-assignment/cli-login/internal/store"
	"github.com/pquerna/otp/totp"
)

const testPassword = "correct horse battery staple"

var ctx = context.Background()

type fixture struct {
	s     *Service
	db    *sql.DB
	path  string
	vault *secure.Vault
	clock atomic.Int64
}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{path: filepath.Join(t.TempDir(), "login.db")}
	var err error
	f.vault, err = secure.NewVault(bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.db, err = store.Open(ctx, f.path, f.vault.ID())
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{SessionTTL: 30 * time.Minute, LockoutDuration: 15 * time.Minute, MaxAttempts: 3, Issuer: "Test Login"}
	f.s, err = New(f.db, f.vault, cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.Store(time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC).UnixNano())
	f.s.now = f.now
	t.Cleanup(func() { f.db.Close() })
	return f
}

func (f *fixture) now() time.Time          { return time.Unix(0, f.clock.Load()).UTC() }
func (f *fixture) advance(d time.Duration) { f.clock.Add(int64(d)) }
func (f *fixture) register(t *testing.T, username string) {
	t.Helper()
	if err := f.s.Register(ctx, username, []byte(testPassword)); err != nil {
		t.Fatal(err)
	}
}
func (f *fixture) login(t *testing.T, username, code string) Session {
	t.Helper()
	session, err := f.s.Login(ctx, username, []byte(testPassword), code)
	if err != nil {
		t.Fatal(err)
	}
	return session
}
func (f *fixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func (f *fixture) enrollment(t *testing.T, session Session) Enrollment {
	t.Helper()
	enrollment, err := f.s.BeginEnable2FA(ctx, session.Token, []byte(testPassword))
	if err != nil {
		t.Fatal(err)
	}
	return enrollment
}
func (f *fixture) enable(t *testing.T, username string) string {
	t.Helper()
	f.register(t, username)
	session := f.login(t, username, "")
	enrollment := f.enrollment(t, session)
	if err := f.s.ConfirmEnable2FA(ctx, session.Token, codeAt(t, enrollment.Secret, f.now())); err != nil {
		t.Fatal(err)
	}
	return enrollment.Secret
}
func codeAt(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	return code
}
func expectError(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("error=%v, want %v", got, want)
	}
}

func TestUsernameValidation(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"Alice", "alice"}, {" ALICE ", "alice"}, {"a.b_c-9", "a.b_c-9"}, {strings.Repeat("a", 32), strings.Repeat("a", 32)},
		{"ab", ""}, {strings.Repeat("a", 33), ""}, {"1alice", ""}, {"a b", ""}, {"用户", ""}, {"alice\x1b[2J", ""}, {"' OR 1=1 --", ""}, {"alice\x00", ""}, {"", ""},
	} {
		got, err := NormalizeUsername(tc.input)
		if (err == nil) != (tc.want != "") || got != tc.want {
			t.Fatalf("input=%q got=%q err=%v", tc.input, got, err)
		}
	}
}

func TestRegistrationAndSessions(t *testing.T) {
	f := setup(t)
	expectError(t, f.s.Register(ctx, "ab", []byte(testPassword)), ErrUsername)
	expectError(t, f.s.Register(ctx, "alice", []byte("short")), secure.ErrPasswordPolicy)
	f.register(t, " Alice ")
	expectError(t, f.s.Register(ctx, "ALICE", []byte(testPassword)), ErrUsernameTaken)
	if f.count(t, "SELECT count(*) FROM users") != 1 {
		t.Fatal("duplicate registration created a user")
	}
	var hash string
	if err := f.db.QueryRow("SELECT password_hash FROM users").Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash == testPassword || !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatal("password stored incorrectly")
	}
	for _, name := range []string{"missing", "' OR 1=1--", ""} {
		_, err := f.s.Login(ctx, name, []byte(testPassword), "")
		expectError(t, err, ErrAuthentication)
	}
	_, err := f.s.Login(ctx, "alice", []byte("wrong password"), "")
	expectError(t, err, ErrAuthentication)
	first := f.login(t, "ALICE", "")
	if first.User.Username != "alice" || first.User.MFAEnabled || first.PreviousLoginAt != nil || first.User.LastLoginAt == nil || !first.User.RegisteredAt.Equal(f.now()) || !first.ExpiresAt.Equal(f.now().Add(30*time.Minute)) {
		t.Fatalf("bad session details: %+v", first)
	}
	var stored string
	if err := f.db.QueryRow("SELECT token_hash FROM sessions").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == first.Token || stored != secure.TokenHash(first.Token) {
		t.Fatal("raw session token persisted")
	}
	if f.count(t, "SELECT failed_attempts FROM users") != 0 {
		t.Fatal("successful login did not reset failures")
	}
	f.advance(time.Second)
	second := f.login(t, "alice", "")
	if first.Token == second.Token || second.PreviousLoginAt == nil || !second.PreviousLoginAt.Equal(*first.User.LastLoginAt) {
		t.Fatal("token rotation/previous login incorrect")
	}
	info, err := f.s.WhoAmI(ctx, second.Token)
	if err != nil || info.Token != "" || !info.User.LastLoginAt.Equal(f.now()) {
		t.Fatal("whoami incorrect", err)
	}
	if err := f.s.Logout(ctx, first.Token); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.WhoAmI(ctx, first.Token)
	expectError(t, err, ErrSession)
	if _, err := f.s.WhoAmI(ctx, second.Token); err != nil {
		t.Fatal("logout revoked unrelated session", err)
	}
	if err := f.s.Logout(ctx, first.Token); err != nil {
		t.Fatal("logout not idempotent", err)
	}
}

func TestSessionBoundaryAndGarbageCollection(t *testing.T) {
	f := setup(t)
	f.register(t, "alice")
	session := f.login(t, "alice", "")
	for _, token := range []string{"", "bad", "' OR 1=1--", strings.Repeat("0", 64)} {
		_, err := f.s.WhoAmI(ctx, token)
		expectError(t, err, ErrSession)
		_, err = f.s.BeginEnable2FA(ctx, token, []byte(testPassword))
		expectError(t, err, ErrSession)
		expectError(t, f.s.ConfirmEnable2FA(ctx, token, "123456"), ErrSession)
		expectError(t, f.s.Disable2FA(ctx, token, []byte(testPassword), "123456"), ErrSession)
		if err := f.s.Logout(ctx, token); err != nil {
			t.Fatal(err)
		}
	}
	f.clock.Store(session.ExpiresAt.Add(-time.Nanosecond).UnixNano())
	if _, err := f.s.WhoAmI(ctx, session.Token); err != nil {
		t.Fatal("session expired early", err)
	}
	f.advance(time.Nanosecond)
	_, err := f.s.WhoAmI(ctx, session.Token)
	expectError(t, err, ErrSession)
	_, err = f.s.BeginEnable2FA(ctx, session.Token, []byte(testPassword))
	expectError(t, err, ErrSession)
	f.login(t, "alice", "")
	if f.count(t, "SELECT count(*) FROM sessions") != 1 {
		t.Fatal("expired session not pruned")
	}
}

func TestLockoutAndExactUnlock(t *testing.T) {
	f := setup(t)
	f.register(t, "alice")
	for i := 1; i <= 3; i++ {
		_, err := f.s.Login(ctx, "alice", []byte("wrong"), "")
		want := ErrAuthentication
		if i == 3 {
			want = ErrLocked
		}
		expectError(t, err, want)
	}
	var deadline int64
	if err := f.db.QueryRow("SELECT locked_until FROM users").Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	if deadline != f.now().Add(15*time.Minute).UnixNano() {
		t.Fatal("wrong lockout duration")
	}
	f.advance(time.Minute)
	_, err := f.s.Login(ctx, "alice", []byte(testPassword), "")
	expectError(t, err, ErrLocked)
	if f.count(t, "SELECT failed_attempts FROM users") != 3 {
		t.Fatal("blocked login modified attempts")
	}
	var unchanged int64
	f.db.QueryRow("SELECT locked_until FROM users").Scan(&unchanged)
	if deadline != unchanged {
		t.Fatal("blocked login extended lockout")
	}
	f.clock.Store(deadline - 1)
	_, err = f.s.Login(ctx, "alice", []byte(testPassword), "")
	expectError(t, err, ErrLocked)
	f.advance(time.Nanosecond)
	f.login(t, "alice", "")
	if f.count(t, "SELECT count(*) FROM users WHERE failed_attempts=0 AND locked_until IS NULL") != 1 {
		t.Fatal("successful unlock did not reset lockout")
	}
}

func TestExpiredLockoutRestartsFailureCounter(t *testing.T) {
	f := setup(t)
	f.register(t, "alice")
	for i := 0; i < 3; i++ {
		f.s.Login(ctx, "alice", []byte("wrong"), "")
	}
	f.advance(15 * time.Minute)
	_, err := f.s.Login(ctx, "alice", []byte("wrong"), "")
	expectError(t, err, ErrAuthentication)
	if f.count(t, "SELECT failed_attempts FROM users") != 1 {
		t.Fatal("expired lockout did not restart counter")
	}
}

func TestMFALifecycleAndRevocation(t *testing.T) {
	f := setup(t)
	f.register(t, "alice")
	a, b := f.login(t, "alice", ""), f.login(t, "alice", "")
	expectError(t, f.s.Disable2FA(ctx, a.Token, []byte(testPassword), "123456"), ErrNotEnabled)
	_, err := f.s.BeginEnable2FA(ctx, a.Token, []byte("wrong"))
	expectError(t, err, ErrAuthentication)
	if f.count(t, "SELECT count(*) FROM mfa_enrollments") != 0 {
		t.Fatal("incorrect password created enrollment")
	}
	enrollment := f.enrollment(t, a)
	expectError(t, f.s.ConfirmEnable2FA(ctx, b.Token, "123456"), ErrEnrollment)
	expectError(t, f.s.ConfirmEnable2FA(ctx, a.Token, "bad"), ErrAuthentication)
	if f.count(t, "SELECT count(*) FROM users WHERE totp_secret IS NOT NULL") != 0 {
		t.Fatal("failed confirmation activated MFA")
	}
	var encrypted []byte
	if err := f.db.QueryRow("SELECT secret FROM mfa_enrollments").Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte(enrollment.Secret)) {
		t.Fatal("pending MFA secret in plaintext")
	}
	initialCode := codeAt(t, enrollment.Secret, f.now())
	if err := f.s.ConfirmEnable2FA(ctx, a.Token, initialCode); err != nil {
		t.Fatal(err)
	}
	if f.count(t, "SELECT count(*) FROM sessions") != 0 || f.count(t, "SELECT count(*) FROM mfa_enrollments") != 0 {
		t.Fatal("MFA enable did not revoke all sessions and enrollments")
	}
	for _, token := range []string{a.Token, b.Token} {
		_, err := f.s.WhoAmI(ctx, token)
		expectError(t, err, ErrSession)
	}
	if err := f.db.QueryRow("SELECT totp_secret FROM users").Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte(enrollment.Secret)) {
		t.Fatal("active secret in plaintext")
	}
	_, err = f.s.Login(ctx, "alice", []byte(testPassword), "")
	expectError(t, err, ErrMFARequired)
	if f.count(t, "SELECT count(*) FROM sessions") != 0 {
		t.Fatal("password-only MFA login created session")
	}
	_, err = f.s.Login(ctx, "alice", []byte(testPassword), initialCode)
	expectError(t, err, ErrAuthentication)
	f.advance(30 * time.Second)
	code := codeAt(t, enrollment.Secret, f.now())
	mfaSession := f.login(t, "alice", code)
	if !mfaSession.User.MFAEnabled {
		t.Fatal("MFA status missing")
	}
	_, err = f.s.BeginEnable2FA(ctx, mfaSession.Token, []byte(testPassword))
	expectError(t, err, ErrAlreadyEnabled)
	_, err = f.s.Login(ctx, "alice", []byte(testPassword), code)
	expectError(t, err, ErrAuthentication)
	expectError(t, f.s.Disable2FA(ctx, mfaSession.Token, []byte("wrong"), code), ErrAuthentication)
	// a full successful login clears failures, use another fresh step first.
	f.advance(30 * time.Second)
	f.login(t, "alice", codeAt(t, enrollment.Secret, f.now()))
	f.advance(30 * time.Second)
	if err := f.s.Disable2FA(ctx, mfaSession.Token, []byte(testPassword), codeAt(t, enrollment.Secret, f.now())); err != nil {
		t.Fatal(err)
	}
	if f.count(t, "SELECT count(*) FROM sessions") != 0 || f.count(t, "SELECT count(*) FROM users WHERE totp_secret IS NULL AND last_totp_step=-1") != 1 {
		t.Fatal("MFA disable failed to revoke/clear")
	}
	if f.login(t, "alice", "").User.MFAEnabled {
		t.Fatal("MFA still enabled")
	}
}

func TestEnrollmentExpirationCancellationAndSessionBinding(t *testing.T) {
	f := setup(t)
	f.register(t, "alice")
	a, b := f.login(t, "alice", ""), f.login(t, "alice", "")
	expectError(t, f.s.ConfirmEnable2FA(ctx, a.Token, "123456"), ErrEnrollment)
	enrollment := f.enrollment(t, a)
	if !enrollment.ExpiresAt.Equal(f.now().Add(5 * time.Minute)) {
		t.Fatal("wrong enrollment TTL")
	}
	f.clock.Store(enrollment.ExpiresAt.UnixNano())
	expectError(t, f.s.ConfirmEnable2FA(ctx, a.Token, codeAt(t, enrollment.Secret, f.now())), ErrEnrollment)
	enrollment = f.enrollment(t, a)
	expectError(t, f.s.ConfirmEnable2FA(ctx, b.Token, codeAt(t, enrollment.Secret, f.now())), ErrEnrollment)
	if err := f.s.CancelEnrollment(ctx, a.Token); err != nil {
		t.Fatal(err)
	}
	expectError(t, f.s.ConfirmEnable2FA(ctx, a.Token, codeAt(t, enrollment.Secret, f.now())), ErrEnrollment)
	f.enrollment(t, a)
	if err := f.s.Logout(ctx, a.Token); err != nil {
		t.Fatal(err)
	}
	if f.count(t, "SELECT count(*) FROM mfa_enrollments") != 0 {
		t.Fatal("logout left enrollment behind")
	}
	f.clock.Store(b.ExpiresAt.Add(-time.Minute).UnixNano())
	short := f.enrollment(t, b)
	if !short.ExpiresAt.Equal(b.ExpiresAt) {
		t.Fatal("enrollment outlived session")
	}
}

func TestMFAFailuresCannotBypassLockout(t *testing.T) {
	f := setup(t)
	secret := f.enable(t, "alice")
	f.advance(30 * time.Second)
	for i := 0; i < 2; i++ {
		_, err := f.s.Login(ctx, "alice", []byte(testPassword), "bad")
		expectError(t, err, ErrAuthentication)
	}
	_, err := f.s.Login(ctx, "alice", []byte(testPassword), "")
	expectError(t, err, ErrMFARequired)
	if f.count(t, "SELECT failed_attempts FROM users") != 2 {
		t.Fatal("password-only success reset MFA failures")
	}
	_, err = f.s.Login(ctx, "alice", []byte(testPassword), "bad")
	expectError(t, err, ErrLocked)
	_, err = f.s.Login(ctx, "alice", []byte(testPassword), codeAt(t, secret, f.now()))
	expectError(t, err, ErrLocked)
	if f.count(t, "SELECT count(*) FROM sessions") != 0 {
		t.Fatal("MFA bypass")
	}
	f.advance(15 * time.Minute)
	f.login(t, "alice", codeAt(t, secret, f.now()))
}

func TestEnrollmentRestartDoesNotResetFailures(t *testing.T) {
	f := setup(t)
	f.register(t, "alice")
	session := f.login(t, "alice", "")
	for i := 0; i < 3; i++ {
		f.enrollment(t, session)
		err := f.s.ConfirmEnable2FA(ctx, session.Token, "bad")
		want := ErrAuthentication
		if i == 2 {
			want = ErrLocked
		}
		expectError(t, err, want)
	}
	_, err := f.s.BeginEnable2FA(ctx, session.Token, []byte(testPassword))
	expectError(t, err, ErrLocked)
	expectError(t, f.s.ConfirmEnable2FA(ctx, session.Token, "123456"), ErrLocked)
}

func TestPersistentSessionsLockoutsAndMFA(t *testing.T) {
	f := setup(t)
	secret := f.enable(t, "alice")
	f.advance(30 * time.Second)
	session := f.login(t, "alice", codeAt(t, secret, f.now()))
	for i := 0; i < 3; i++ {
		f.s.Login(ctx, "alice", []byte("bad"), "")
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.db, err = store.Open(ctx, f.path, f.vault.ID())
	if err != nil {
		t.Fatal(err)
	}
	f.s.db = f.db
	if _, err := f.s.WhoAmI(ctx, session.Token); err != nil {
		t.Fatal("persisted session missing", err)
	}
	_, err = f.s.Login(ctx, "alice", []byte(testPassword), codeAt(t, secret, f.now()))
	expectError(t, err, ErrLocked)
	f.advance(15 * time.Minute)
	f.login(t, "alice", codeAt(t, secret, f.now()))
}

func TestConcurrentFailuresAndOTPReplayAcrossConnections(t *testing.T) {
	f := setup(t)
	f.s.cfg.MaxAttempts = 5
	secret := f.enable(t, "alice")
	f.advance(30 * time.Second)
	otherDB, err := store.Open(ctx, f.path, f.vault.ID())
	if err != nil {
		t.Fatal(err)
	}
	defer otherDB.Close()
	other, err := New(otherDB, f.vault, f.s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	other.now = f.now
	services := []*Service{f.s, other}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		service := services[i%2]
		wg.Go(func() {
			_, err := service.Login(ctx, "alice", []byte("bad"), "")
			if !errors.Is(err, ErrAuthentication) && !errors.Is(err, ErrLocked) {
				t.Errorf("unexpected concurrent error: %v", err)
			}
		})
	}
	wg.Wait()
	if f.count(t, "SELECT failed_attempts FROM users") != 5 {
		t.Fatal("concurrent attempts were lost or active lockout incremented")
	}
	f.advance(15 * time.Minute)
	code := codeAt(t, secret, f.now())
	var successes atomic.Int32
	for _, service := range services {
		wg.Go(func() {
			_, err := service.Login(ctx, "alice", []byte(testPassword), code)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrAuthentication) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 || f.count(t, "SELECT count(*) FROM sessions") != 1 {
		t.Fatal("same TOTP accepted concurrently")
	}
}

func TestConcurrentRegistration(t *testing.T) {
	f := setup(t)
	var success atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Go(func() {
			err := f.s.Register(ctx, "alice", []byte(testPassword))
			if err == nil {
				success.Add(1)
			} else if !errors.Is(err, ErrUsernameTaken) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if success.Load() != 1 || f.count(t, "SELECT count(*) FROM users") != 1 {
		t.Fatal("duplicate concurrent registrations")
	}
}

func TestAtomicLoginRollbackAndCorruptSecret(t *testing.T) {
	f := setup(t)
	secret := f.enable(t, "alice")
	f.advance(30 * time.Second)
	code := codeAt(t, secret, f.now())
	if _, err := f.db.Exec(`CREATE TRIGGER fail_session BEFORE UPDATE ON users BEGIN SELECT RAISE(ABORT,'simulated write failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Login(ctx, "alice", []byte(testPassword), code); err == nil {
		t.Fatal("failed transaction authenticated")
	}
	if f.count(t, "SELECT count(*) FROM sessions") != 0 {
		t.Fatal("partial session persisted")
	}
	if _, err := f.db.Exec("DROP TRIGGER fail_session"); err != nil {
		t.Fatal(err)
	}
	session := f.login(t, "alice", code) // the failed commit must not consume the code
	if _, err := f.db.Exec("UPDATE users SET totp_secret=?", []byte("tampered")); err != nil {
		t.Fatal(err)
	}
	f.advance(30 * time.Second)
	if _, err := f.s.Login(ctx, "alice", []byte(testPassword), codeAt(t, secret, f.now())); err == nil {
		t.Fatal("corrupt secret bypassed MFA")
	}
	if err := f.s.Disable2FA(ctx, session.Token, []byte(testPassword), codeAt(t, secret, f.now())); err == nil {
		t.Fatal("corrupt secret disabled MFA")
	}
}

func TestDatabaseErrorsAndCancelledContextFailClosed(t *testing.T) {
	f := setup(t)
	f.register(t, "alice")
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.s.Login(cancelled, "alice", []byte(testPassword), ""); err == nil {
		t.Fatal("cancelled login succeeded")
	}
	if _, err := f.s.WhoAmI(cancelled, strings.Repeat("a", 64)); err == nil {
		t.Fatal("cancelled lookup succeeded")
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Login(ctx, "alice", []byte(testPassword), ""); err == nil {
		t.Fatal("closed DB authenticated")
	}
	if err := f.s.Register(ctx, "bob", []byte(testPassword)); err == nil {
		t.Fatal("closed DB registered user")
	}
}

func TestDisableRequiresFreshCodeAndHonorsLockout(t *testing.T) {
	f := setup(t)
	secret := f.enable(t, "alice")
	f.advance(30 * time.Second)
	code := codeAt(t, secret, f.now())
	session := f.login(t, "alice", code)
	expectError(t, f.s.ConfirmEnable2FA(ctx, session.Token, code), ErrAlreadyEnabled)
	expectError(t, f.s.Disable2FA(ctx, session.Token, []byte(testPassword), code), ErrAuthentication)
	expectError(t, f.s.Disable2FA(ctx, session.Token, []byte(testPassword), "bad"), ErrAuthentication)
	expectError(t, f.s.Disable2FA(ctx, session.Token, []byte(testPassword), ""), ErrLocked)
	if f.count(t, "SELECT count(*) FROM users WHERE totp_secret IS NOT NULL") != 1 || f.count(t, "SELECT count(*) FROM sessions") != 1 {
		t.Fatal("failed disable mutated MFA/session state")
	}
	f.advance(30 * time.Second)
	expectError(t, f.s.Disable2FA(ctx, session.Token, []byte(testPassword), codeAt(t, secret, f.now())), ErrLocked)
	f.advance(15 * time.Minute)
	if err := f.s.Disable2FA(ctx, session.Token, []byte(testPassword), codeAt(t, secret, f.now())); err != nil {
		t.Fatal(err)
	}
}

func TestMFATransactionRollsBackWhenRevocationFails(t *testing.T) {
	f := setup(t)
	f.register(t, "alice")
	session := f.login(t, "alice", "")
	enrollment := f.enrollment(t, session)
	if _, err := f.db.Exec(`CREATE TRIGGER fail_revocation BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT,'simulated revocation failure'); END`); err != nil {
		t.Fatal(err)
	}
	code := codeAt(t, enrollment.Secret, f.now())
	if err := f.s.ConfirmEnable2FA(ctx, session.Token, code); err == nil {
		t.Fatal("MFA enabled despite failed session revocation")
	}
	info, err := f.s.WhoAmI(ctx, session.Token)
	if err != nil || info.User.MFAEnabled {
		t.Fatal("partially committed MFA transition", err)
	}
	if f.count(t, "SELECT count(*) FROM mfa_enrollments") != 1 {
		t.Fatal("enrollment lost on rollback")
	}
	if _, err := f.db.Exec("DROP TRIGGER fail_revocation"); err != nil {
		t.Fatal(err)
	}
	if err := f.s.ConfirmEnable2FA(ctx, session.Token, code); err != nil {
		t.Fatal("rolled back confirmation consumed TOTP", err)
	}
}

func TestAccountsAreIsolated(t *testing.T) {
	f := setup(t)
	f.register(t, "alice")
	f.register(t, "bobby")
	alice, bob := f.login(t, "alice", ""), f.login(t, "bobby", "")
	for i := 0; i < 3; i++ {
		f.s.Login(ctx, "alice", []byte("bad"), "")
	}
	if f.count(t, "SELECT failed_attempts FROM users WHERE username='bobby'") != 0 {
		t.Fatal("one account locked another")
	}
	f.advance(15 * time.Minute)
	enrollment := f.enrollment(t, alice)
	if err := f.s.ConfirmEnable2FA(ctx, alice.Token, codeAt(t, enrollment.Secret, f.now())); err != nil {
		t.Fatal(err)
	}
	info, err := f.s.WhoAmI(ctx, bob.Token)
	if err != nil || info.User.Username != "bobby" || info.User.MFAEnabled {
		t.Fatal("MFA transition affected another account", err)
	}
}

func TestSessionExpirationDuringReauthentication(t *testing.T) {
	f := setup(t)
	f.register(t, "alice")
	session := f.login(t, "alice", "")
	start := f.now()
	var calls atomic.Int32
	f.s.now = func() time.Time {
		if calls.Add(1) == 1 {
			return start
		}
		return session.ExpiresAt
	}
	_, err := f.s.BeginEnable2FA(ctx, session.Token, []byte(testPassword))
	expectError(t, err, ErrSession)
	if f.count(t, "SELECT count(*) FROM mfa_enrollments") != 0 {
		t.Fatal("reauthentication granted enrollment after expiry")
	}
}

func TestNewRejectsUnsafeConfiguration(t *testing.T) {
	f := setup(t)
	for _, cfg := range []config.Config{{}, {MaxAttempts: 0, SessionTTL: time.Minute, LockoutDuration: time.Minute, Issuer: "test"}, {MaxAttempts: 3, SessionTTL: 0, LockoutDuration: time.Minute, Issuer: "test"}} {
		if _, err := New(f.db, f.vault, cfg); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	if _, err := New(nil, f.vault, f.s.cfg); err == nil {
		t.Fatal("nil DB accepted")
	}
	if _, err := New(f.db, nil, f.s.cfg); err == nil {
		t.Fatal("nil vault accepted")
	}
}

func FuzzNormalizeUsername(f *testing.F) {
	f.Add("alice")
	f.Add("' OR 1=1--")
	f.Add("\x1b[2J")
	f.Fuzz(func(t *testing.T, input string) {
		normalized, err := NormalizeUsername(input)
		if err == nil && (!usernamePattern.MatchString(normalized) || len(normalized) > 32) {
			t.Fatal("unsafe username accepted")
		}
	})
}
