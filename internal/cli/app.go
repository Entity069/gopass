package cli

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/chzyer/readline"
	"github.com/osto-assignment/cli-login/internal/auth"
	"github.com/osto-assignment/cli-login/internal/secure"
)

type Backend interface {
	Register(context.Context, string, []byte) error
	Login(context.Context, string, []byte, string) (auth.Session, error)
	WhoAmI(context.Context, string) (auth.Session, error)
	Logout(context.Context, string) error
	BeginEnable2FA(context.Context, string, []byte) (auth.Enrollment, error)
	ConfirmEnable2FA(context.Context, string, string) error
	CancelEnrollment(context.Context, string) error
	Disable2FA(context.Context, string, []byte, string) error
}

type App struct {
	backend Backend
	console Console
	token   string
}

var errPasswordMismatch = errors.New("passwords do not match")

func New(backend Backend, console Console) *App { return &App{backend: backend, console: console} }

func (a *App) Run(ctx context.Context) (result error) {
	a.console.Printf("CLI Login: Secure local authentication\nType help for commands. Tab completes; ↑/↓ recalls commands.\nPasswords and codes are hidden. Ctrl+C cancels a form or exits at the command prompt.\n\n")
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := a.backend.Logout(cleanup, a.token); err != nil {
			a.console.Printf("Warning: session cleanup failed; it will expire automatically.\n")
			result = errors.Join(result, err)
		}
		a.token = ""
	}()
	for ctx.Err() == nil {
		a.refresh(ctx)
		line, err := a.console.Command(a.token != "")
		if errors.Is(err, io.EOF) || errors.Is(err, readline.ErrInterrupt) || ctx.Err() != nil {
			a.console.Printf("Goodbye.\n")
			return nil
		}
		if err != nil {
			return err
		}
		exit, err := a.execute(ctx, line)
		if exit || errors.Is(err, io.EOF) {
			a.console.Printf("Goodbye.\n")
			return nil
		}
		if err != nil {
			a.showError(err)
		}
	}
	return nil
}

func (a *App) refresh(ctx context.Context) {
	if a.token == "" {
		return
	}
	_, err := a.backend.WhoAmI(ctx, a.token)
	if errors.Is(err, auth.ErrSession) {
		a.token = ""
		a.console.Printf("Session expired or revoked. Please log in again.\n")
	}
}

func (a *App) execute(ctx context.Context, line string) (bool, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false, nil
	}
	if len(fields) != 1 {
		a.console.Printf("Enter a command without arguments; credentials are collected in private prompts.\n")
		return false, nil
	}
	command := strings.ToLower(fields[0])
	if !slices.Contains(guestCommands, command) && !slices.Contains(memberCommands, command) {
		a.console.Printf("Unknown command. Type help for available commands.\n")
		return false, nil
	}

	if err := a.console.Remember(command); err != nil {
		return false, err
	}
	a.refresh(ctx)
	if command == "exit" {
		return true, nil
	}
	if command == "help" {
		a.help()
		return false, nil
	}
	if a.token == "" && !slices.Contains(guestCommands, command) {
		a.console.Printf("Please log in first.\n")
		return false, nil
	}
	if a.token != "" && (command == "login" || command == "register") {
		a.console.Printf("Log out before logging in or registering another account.\n")
		return false, nil
	}
	switch command {
	case "register":
		return false, a.register(ctx)
	case "login":
		return false, a.login(ctx)
	case "whoami":
		session, err := a.backend.WhoAmI(ctx, a.token)
		if err == nil {
			a.details(session, false)
		}
		return false, err
	case "enable-2fa":
		return false, a.enable(ctx)
	case "disable-2fa":
		return false, a.disable(ctx)
	case "logout":
		if err := a.backend.Logout(ctx, a.token); err != nil {
			return false, err
		}
		a.token = ""
		a.console.Printf("Logged out.\n")
	}
	return false, nil
}

func (a *App) register(ctx context.Context) error {
	username, err := a.console.Input("Username (3–32 characters): ")
	if err != nil {
		return err
	}
	if _, err := auth.NormalizeUsername(username); err != nil {
		return err
	}
	password, err := a.console.Secret("Password (at least 8 characters): ")
	defer clear(password)
	if err != nil {
		return err
	}
	if err := secure.ValidatePassword(password); err != nil {
		return err
	}
	confirmation, err := a.console.Secret("Confirm password: ")
	defer clear(confirmation)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(password, confirmation) != 1 {
		return errPasswordMismatch
	}
	if err := a.backend.Register(ctx, username, password); err != nil {
		return err
	}
	a.console.Printf("Account created. Use login to sign in.\n")
	return nil
}

func (a *App) login(ctx context.Context) error {
	username, err := a.console.Input("Username: ")
	if err != nil {
		return err
	}
	password, err := a.console.Secret("Password: ")
	defer clear(password)
	if err != nil {
		return err
	}
	session, err := a.backend.Login(ctx, username, password, "")
	if errors.Is(err, auth.ErrMFARequired) {
		code, inputErr := a.console.Secret("Authenticator code (6 digits; use a fresh code): ")
		defer clear(code)
		if inputErr != nil {
			return inputErr
		}
		session, err = a.backend.Login(ctx, username, password, string(code))
	}
	if err != nil {
		return err
	}
	a.token = session.Token
	a.console.Printf("Login successful.\n")
	a.details(session, true)
	return nil
}

func (a *App) enable(ctx context.Context) error {
	password, err := a.console.Secret("Current password: ")
	defer clear(password)
	if err != nil {
		return err
	}
	enrollment, err := a.backend.BeginEnable2FA(ctx, a.token, password)
	if err != nil {
		return err
	}
	token := a.token
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := a.backend.CancelEnrollment(cleanup, token); err != nil {
			a.console.Printf("Warning: pending setup cleanup failed; it will expire automatically.\n")
		}
	}()
	a.console.Printf("Add a time-based key in Google Authenticator (6 digits, 30 seconds).\nKeep this setup key private; it is displayed only during setup.\nSetup key: %s\nProvisioning URI: %s\nSetup expires: %s\n", enrollment.Secret, enrollment.URL, formatTime(enrollment.ExpiresAt))
	code, err := a.console.Secret("Enter the authenticator code to confirm (Ctrl+C cancels): ")
	defer clear(code)
	if err != nil {
		return err
	}
	if err := a.backend.ConfirmEnable2FA(ctx, a.token, string(code)); err != nil {
		return err
	}
	a.token = ""
	a.console.Printf("2FA enabled. All sessions ended. Wait for a fresh authenticator code, then log in again.\n")
	return nil
}

func (a *App) disable(ctx context.Context) error {
	password, err := a.console.Secret("Current password: ")
	defer clear(password)
	if err != nil {
		return err
	}
	code, err := a.console.Secret("Fresh authenticator code (6 digits): ")
	defer clear(code)
	if err != nil {
		return err
	}
	if err := a.backend.Disable2FA(ctx, a.token, password, string(code)); err != nil {
		return err
	}
	a.token = ""
	a.console.Printf("2FA disabled. All sessions ended. Log in again with your password.\n")
	return nil
}

func (a *App) details(session auth.Session, afterLogin bool) {
	mfa := "disabled"
	if session.User.MFAEnabled {
		mfa = "enabled"
	}
	last := session.User.LastLoginAt
	label := "Last login"
	if afterLogin {
		last = session.PreviousLoginAt
		label = "Last login (before this session)"
	}
	lastText := "None! This is your first login"
	if last != nil {
		lastText = formatTime(*last)
	}
	a.console.Printf("Username: %s\nRegistered: %s\nMFA: %s\nSession expires: %s\n%s: %s\n", session.User.Username, formatTime(session.User.RegisteredAt), mfa, formatTime(session.ExpiresAt), label, lastText)
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func (a *App) help() {
	if a.token == "" {
		a.console.Printf("register     Create a new account\nlogin        Sign in (authenticator code when enabled)\n")
	} else {
		a.console.Printf("whoami       Show account and session details\nenable-2fa   Enroll an authenticator after password confirmation\ndisable-2fa  Remove 2FA using password and a fresh code\nlogout       End this session\n")
	}
	a.console.Printf("help         List available commands\nexit         End this session and quit\n\nCommands accept no arguments. History contains commands only and is not saved to disk.\n")
}

func (a *App) showError(err error) {
	switch {
	case errors.Is(err, readline.ErrInterrupt):
		a.console.Printf("Cancelled.\n")
	case errors.Is(err, auth.ErrLocked), errors.Is(err, auth.ErrAuthentication):
		a.console.Printf("Error: %s\n", auth.ErrAuthentication)
	case errors.Is(err, auth.ErrSession):
		a.token = ""
		a.console.Printf("Error: %s\n", err)
	case errors.Is(err, auth.ErrUsername), errors.Is(err, auth.ErrUsernameTaken), errors.Is(err, secure.ErrPasswordPolicy), errors.Is(err, auth.ErrAlreadyEnabled), errors.Is(err, auth.ErrNotEnabled), errors.Is(err, auth.ErrEnrollment), errors.Is(err, auth.ErrMFARequired):
		a.console.Printf("Error: %s\n", err)
	case errors.Is(err, errPasswordMismatch):
		a.console.Printf("Error: passwords do not match.\n")
	default:
		a.console.Printf("Operation failed. Check database availability, permissions and configuration.\n")
	}
}
