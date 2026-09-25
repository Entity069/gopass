package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chzyer/readline"
	"github.com/osto-assignment/cli-login/internal/auth"
)

type input struct {
	value string
	err   error
}
type fakeConsole struct {
	commands, inputs, secrets []input
	history                   []string
	secretBuffers             [][]byte
	output                    bytes.Buffer
	historyErr                error
}

func next(queue *[]input) (string, error) {
	if len(*queue) == 0 {
		return "", io.EOF
	}
	item := (*queue)[0]
	*queue = (*queue)[1:]
	return item.value, item.err
}
func (c *fakeConsole) Command(bool) (string, error) { return next(&c.commands) }
func (c *fakeConsole) Input(string) (string, error) { return next(&c.inputs) }
func (c *fakeConsole) Secret(string) ([]byte, error) {
	value, err := next(&c.secrets)
	b := []byte(value)
	c.secretBuffers = append(c.secretBuffers, b)
	return b, err
}
func (c *fakeConsole) Remember(command string) error {
	c.history = append(c.history, command)
	return c.historyErr
}
func (c *fakeConsole) Printf(format string, args ...any) { fmt.Fprintf(&c.output, format, args...) }

type fakeBackend struct {
	registerErr, loginErr, sessionErr, logoutErr, beginErr, confirmErr, disableErr error
	mfa                                                                            bool
	loginCodes                                                                     []string
	registered, logouts, begins, confirmations, cancellations, disables            int
}

func (b *fakeBackend) Register(context.Context, string, []byte) error {
	b.registered++
	return b.registerErr
}
func (b *fakeBackend) Login(_ context.Context, _ string, _ []byte, code string) (auth.Session, error) {
	b.loginCodes = append(b.loginCodes, code)
	if b.mfa && code == "" {
		return auth.Session{}, auth.ErrMFARequired
	}
	return testSession(), b.loginErr
}
func (b *fakeBackend) WhoAmI(context.Context, string) (auth.Session, error) {
	return testSession(), b.sessionErr
}
func (b *fakeBackend) Logout(context.Context, string) error { b.logouts++; return b.logoutErr }
func (b *fakeBackend) BeginEnable2FA(context.Context, string, []byte) (auth.Enrollment, error) {
	b.begins++
	return auth.Enrollment{Secret: "SETUPSECRET", URL: "otpauth://test", ExpiresAt: time.Now().Add(time.Minute)}, b.beginErr
}
func (b *fakeBackend) ConfirmEnable2FA(context.Context, string, string) error {
	b.confirmations++
	return b.confirmErr
}
func (b *fakeBackend) CancelEnrollment(context.Context, string) error { b.cancellations++; return nil }
func (b *fakeBackend) Disable2FA(context.Context, string, []byte, string) error {
	b.disables++
	return b.disableErr
}
func testSession() auth.Session {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	return auth.Session{Token: strings.Repeat("a", 64), User: auth.User{Username: "alice", RegisteredAt: now, LastLoginAt: &now}, ExpiresAt: now.Add(30 * time.Minute)}
}
func values(items ...string) []input {
	result := make([]input, len(items))
	for i, item := range items {
		result[i] = input{value: item}
	}
	return result
}

func TestCommandHistoryAndAccessControl(t *testing.T) {
	c := &fakeConsole{}
	b := &fakeBackend{}
	a := New(b, c)
	for _, line := range []string{"", "   ", "arbitrary-secret", "login secret password", "whoami", "enable-2fa", "disable-2fa", "logout", "HELP"} {
		if _, err := a.execute(context.Background(), line); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(c.history, []string{"whoami", "enable-2fa", "disable-2fa", "logout", "help"}) {
		t.Fatalf("unsafe history: %v", c.history)
	}
	if strings.Contains(c.output.String(), "arbitrary-secret") || strings.Contains(c.output.String(), "secret password") {
		t.Fatal("unknown input echoed")
	}
	if b.begins != 0 || b.disables != 0 || b.logouts != 0 {
		t.Fatal("guest invoked protected action")
	}
	if strings.Contains(c.output.String(), "whoami       Show") {
		t.Fatal("guest help showed member commands")
	}
	a.token = "token"
	c.output.Reset()
	for _, line := range []string{"login", "register", "help", "whoami"} {
		if _, err := a.execute(context.Background(), line); err != nil {
			t.Fatal(err)
		}
	}
	if b.registered != 0 || len(b.loginCodes) != 0 {
		t.Fatal("member allowed to reauthenticate over current session")
	}
	for _, text := range []string{"Log out before", "whoami", "Username: alice", "Registered:", "MFA: disabled", "Session expires:", "Last login:"} {
		if !strings.Contains(c.output.String(), text) {
			t.Fatal("missing feedback", text)
		}
	}
}

func TestRegistrationConfirmationAndClearing(t *testing.T) {
	for _, tc := range []struct {
		name, user, password, confirmation string
		wantCalls                          int
		wantErr                            bool
	}{
		{"success", "alice", "correct horse battery staple", "correct horse battery staple", 1, false},
		{"mismatch", "alice", "correct horse battery staple", "different password here", 0, true},
		{"weak", "alice", "short", "short", 0, true},
		{"invalid username", "x", "correct horse battery staple", "correct horse battery staple", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &fakeConsole{inputs: values(tc.user), secrets: values(tc.password, tc.confirmation)}
			b := &fakeBackend{}
			err := New(b, c).register(context.Background())
			if (err != nil) != tc.wantErr || b.registered != tc.wantCalls {
				t.Fatal("unexpected registration result", err, b.registered)
			}
			for _, secret := range c.secretBuffers {
				if !bytes.Equal(secret, make([]byte, len(secret))) {
					t.Fatal("password buffer not cleared")
				}
			}
			if strings.Contains(c.output.String(), tc.password) {
				t.Fatal("password exposed")
			}
		})
	}
}

func TestLoginPromptsMFAOnlyWhenRequired(t *testing.T) {
	for _, mfa := range []bool{false, true} {
		c := &fakeConsole{inputs: values("alice"), secrets: values("correct horse battery staple", "123456")}
		b := &fakeBackend{mfa: mfa}
		a := New(b, c)
		if err := a.login(context.Background()); err != nil {
			t.Fatal(err)
		}
		want := []string{""}
		if mfa {
			want = append(want, "123456")
		}
		if !reflect.DeepEqual(b.loginCodes, want) || a.token == "" {
			t.Fatal("wrong MFA flow")
		}
		for _, text := range []string{"Login successful", "Username: alice", "Registered:", "MFA:", "Session expires:", "Last login (before this session): None! This is your first login"} {
			if !strings.Contains(c.output.String(), text) {
				t.Fatal("missing login details", text)
			}
		}
		for _, secret := range c.secretBuffers {
			if !bytes.Equal(secret, make([]byte, len(secret))) {
				t.Fatal("secret buffer not cleared")
			}
		}
	}
	c := &fakeConsole{inputs: values("alice"), secrets: values("bad")}
	b := &fakeBackend{loginErr: auth.ErrAuthentication}
	a := New(b, c)
	if err := a.login(context.Background()); !errors.Is(err, auth.ErrAuthentication) || a.token != "" {
		t.Fatal("failed login retained a session")
	}
}

func TestMFASetupAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name                string
		codeErr, confirmErr error
		wantToken           bool
		confirmations       int
	}{
		{"confirmed", nil, nil, false, 1}, {"bad code", nil, auth.ErrAuthentication, true, 1}, {"cancelled", readline.ErrInterrupt, nil, true, 0}, {"EOF", io.EOF, nil, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &fakeConsole{secrets: []input{{value: "correct horse battery staple"}, {value: "123456", err: tc.codeErr}}}
			b := &fakeBackend{confirmErr: tc.confirmErr}
			a := New(b, c)
			a.token = "token"
			err := a.enable(context.Background())
			if (err == nil) != (tc.codeErr == nil && tc.confirmErr == nil) || (a.token != "") != tc.wantToken || b.confirmations != tc.confirmations || b.cancellations != 1 {
				t.Fatal("incorrect enrollment cleanup", err)
			}
			if !strings.Contains(c.output.String(), "Setup key: SETUPSECRET") {
				t.Fatal("missing setup instructions")
			}
		})
	}
	c := &fakeConsole{secrets: values("bad")}
	b := &fakeBackend{beginErr: auth.ErrAuthentication}
	a := New(b, c)
	a.token = "token"
	if err := a.enable(context.Background()); err == nil || strings.Contains(c.output.String(), "SETUPSECRET") {
		t.Fatal("setup secret exposed before password verification")
	}
}

func TestDisableMFAAndLogout(t *testing.T) {
	c := &fakeConsole{secrets: values("correct horse battery staple", "123456")}
	b := &fakeBackend{}
	a := New(b, c)
	a.token = "token"
	if err := a.disable(context.Background()); err != nil || a.token != "" || b.disables != 1 {
		t.Fatal("disable failed", err)
	}
	a.token = "token"
	if _, err := a.execute(context.Background(), "logout"); err != nil || a.token != "" || b.logouts != 1 {
		t.Fatal("logout failed", err)
	}
	a.token = "token"
	b.logoutErr = errors.New("database unavailable")
	if _, err := a.execute(context.Background(), "logout"); err == nil || a.token == "" {
		t.Fatal("failed logout reported success")
	}
}

func TestExpiredSessionCheckedAfterPrompt(t *testing.T) {
	c := &fakeConsole{}
	b := &fakeBackend{sessionErr: auth.ErrSession}
	a := New(b, c)
	a.token = "old"
	if _, err := a.execute(context.Background(), "enable-2fa"); err != nil {
		t.Fatal(err)
	}
	if a.token != "" || b.begins != 0 || !strings.Contains(c.output.String(), "Session expired or revoked") {
		t.Fatal("expired session dispatched protected command")
	}
}

func TestRunExitEOFInterruptAndCleanup(t *testing.T) {
	for _, tc := range []struct {
		name     string
		commands []input
	}{
		{"exit", values("help", "exit")}, {"EOF", nil}, {"interrupt", []input{{err: readline.ErrInterrupt}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &fakeConsole{commands: tc.commands}
			b := &fakeBackend{}
			a := New(b, c)
			a.token = "token"
			if err := a.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			if b.logouts != 1 || a.token != "" {
				t.Fatal("exit did not clean session")
			}
		})
	}
	c := &fakeConsole{commands: values("register", "exit"), inputs: []input{{err: readline.ErrInterrupt}}}
	b := &fakeBackend{}
	if err := New(b, c).Run(context.Background()); err != nil || !strings.Contains(c.output.String(), "Cancelled") {
		t.Fatal("form interrupt did not return to shell", err)
	}
	c = &fakeConsole{commands: values("exit")}
	b = &fakeBackend{logoutErr: errors.New("cleanup failed")}
	if err := New(b, c).Run(context.Background()); err == nil || !strings.Contains(c.output.String(), "cleanup failed") {
		t.Fatal("failed cleanup hidden")
	}
}

func TestErrorsDoNotLeakInternalDetails(t *testing.T) {
	c := &fakeConsole{}
	a := New(&fakeBackend{}, c)
	a.showError(errors.New("sensitive database details"))
	if strings.Contains(c.output.String(), "sensitive") || !strings.Contains(c.output.String(), "Operation failed") {
		t.Fatal("internal error leaked")
	}
	c.output.Reset()
	a.showError(auth.ErrLocked)
	locked := c.output.String()
	c.output.Reset()
	a.showError(auth.ErrAuthentication)
	if c.output.String() != locked {
		t.Fatal("lockout reveals account state")
	}
	a.token = "token"
	a.showError(auth.ErrSession)
	if a.token != "" {
		t.Fatal("invalid session not cleared")
	}
}

func TestDetailsPreviousLoginAndMFA(t *testing.T) {
	c := &fakeConsole{}
	a := New(&fakeBackend{}, c)
	session := testSession()
	session.User.MFAEnabled = true
	session.PreviousLoginAt = session.User.LastLoginAt
	a.details(session, true)
	if !strings.Contains(c.output.String(), "MFA: enabled") || !strings.Contains(c.output.String(), "Last login (before this session): 2026-09-25T12:00:00Z") {
		t.Fatal("incorrect previous login display")
	}
}
