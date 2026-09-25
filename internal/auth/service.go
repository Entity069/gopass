package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/osto-assignment/cli-login/internal/config"
	"github.com/osto-assignment/cli-login/internal/secure"
)

var (
	ErrUsername       = errors.New("username must be 3–32 ASCII characters, start with a letter, and contain only letters, digits, dots, underscores or hyphens")
	ErrUsernameTaken  = errors.New("that username is already registered")
	ErrAuthentication = errors.New("authentication failed; check your credentials/code or try again after the lockout period")
	ErrLocked         = errors.New("account temporarily locked")
	ErrMFARequired    = errors.New("an authenticator code is required")
	ErrSession        = errors.New("session expired or revoked; please log in again")
	ErrAlreadyEnabled = errors.New("2FA is already enabled")
	ErrNotEnabled     = errors.New("2FA is not enabled")
	ErrEnrollment     = errors.New("2FA setup expired or was not started; run enable-2fa again")
)

var usernamePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{2,31}$`)

type User struct {
	ID           int64
	Username     string
	RegisteredAt time.Time
	LastLoginAt  *time.Time
	MFAEnabled   bool
}

type Session struct {
	Token           string
	User            User
	ExpiresAt       time.Time
	PreviousLoginAt *time.Time
}

type Enrollment struct {
	Secret    string
	URL       string
	ExpiresAt time.Time
}

type Service struct {
	db        *sql.DB
	vault     *secure.Vault
	cfg       config.Config
	passwords secure.Passwords
	dummyHash string
	now       func() time.Time
}

func New(db *sql.DB, vault *secure.Vault, cfg config.Config) (*Service, error) {
	if db == nil || vault == nil || cfg.MaxAttempts < 1 || cfg.MaxAttempts > 20 || cfg.SessionTTL < time.Second || cfg.SessionTTL > 24*time.Hour || cfg.LockoutDuration < time.Second || cfg.LockoutDuration > 24*time.Hour || cfg.Issuer == "" {
		return nil, errors.New("invalid authentication configuration")
	}
	hasher := secure.Passwords{}
	dummy, err := hasher.Hash([]byte("dummy-password-never-used-for-authentication"))
	if err != nil {
		return nil, err
	}
	return &Service{db: db, vault: vault, cfg: cfg, passwords: hasher, dummyHash: dummy, now: time.Now}, nil
}

func NormalizeUsername(username string) (string, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if !usernamePattern.MatchString(username) {
		return "", ErrUsername
	}
	return username, nil
}

func (s *Service) Register(ctx context.Context, username string, password []byte) error {
	username, err := NormalizeUsername(username)
	if err != nil {
		return err
	}
	hash, err := s.passwords.Hash(password)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?) ON CONFLICT(username) DO NOTHING`, username, hash, s.now().UnixNano())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrUsernameTaken
	}
	return nil
}

// MFA requires password and code in one login, avoids db-bound input and bypassable in memory verification
func (s *Service) Login(ctx context.Context, username string, password []byte, code string) (Session, error) {
	var result Session
	err := s.transact(ctx, func(tx *sql.Tx) error {
		name, nameErr := NormalizeUsername(username)
		u, err := userByName(ctx, tx, name)
		if errors.Is(err, sql.ErrNoRows) || nameErr != nil {
			s.passwords.Verify(s.dummyHash, password)
			return ErrAuthentication
		}
		if err != nil {
			return err
		}
		if err := s.checkPassword(ctx, tx, &u, password); err != nil {
			return err
		}
		now := s.now()
		step := u.lastStep
		if u.User.MFAEnabled {
			if code == "" {
				return ErrMFARequired
			}
			step, err = s.checkCode(ctx, tx, &u, code, now)
			if err != nil {
				return err
			}
		}
		token, err := secure.NewToken()
		if err != nil {
			return err
		}
		expires := now.Add(s.cfg.SessionTTL)
		if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at<=?", now.UnixNano()); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM mfa_enrollments WHERE expires_at<=?", now.UnixNano()); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)`, secure.TokenHash(token), u.ID, now.UnixNano(), expires.UnixNano()); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET last_login_at=?,last_totp_step=?,failed_attempts=0,locked_until=NULL WHERE id=?`, now.UnixNano(), step, u.ID); err != nil {
			return err
		}
		previous := u.LastLoginAt
		u.LastLoginAt = &now
		result = Session{Token: token, User: u.User, ExpiresAt: expires, PreviousLoginAt: previous}
		return nil
	})
	if err != nil {
		return Session{}, err
	}
	return result, nil
}

func (s *Service) WhoAmI(ctx context.Context, token string) (Session, error) {
	var result Session
	err := s.transact(ctx, func(tx *sql.Tx) error {
		u, expires, err := sessionUser(ctx, tx, token, s.now())
		if err != nil {
			return err
		}
		result = Session{User: u.User, ExpiresAt: expires}
		return nil
	})
	return result, err
}

func (s *Service) Logout(ctx context.Context, token string) error {
	if !secure.ValidToken(token) {
		return nil
	}
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash=?", secure.TokenHash(token))
	return err
}

func (s *Service) BeginEnable2FA(ctx context.Context, token string, password []byte) (Enrollment, error) {
	var result Enrollment
	err := s.transact(ctx, func(tx *sql.Tx) error {
		u, expires, err := sessionUser(ctx, tx, token, s.now())
		if err != nil {
			return err
		}
		if u.MFAEnabled {
			return ErrAlreadyEnabled
		}
		if err := s.checkPassword(ctx, tx, &u, password); err != nil {
			return err
		}
		if !s.now().Before(expires) {
			return ErrSession
		}
		key, err := secure.NewTOTP(s.cfg.Issuer, u.Username)
		if err != nil {
			return err
		}
		deadline := s.now().Add(5 * time.Minute)
		if expires.Before(deadline) {
			deadline = expires
		}
		hash := secure.TokenHash(token)
		ciphertext := s.vault.Seal([]byte(key.Secret()), "enrollment:"+hash)
		_, err = tx.ExecContext(ctx, `INSERT INTO mfa_enrollments(session_hash,secret,expires_at) VALUES(?,?,?) ON CONFLICT(session_hash) DO UPDATE SET secret=excluded.secret,expires_at=excluded.expires_at`, hash, ciphertext, deadline.UnixNano())
		if err != nil {
			return err
		}
		result = Enrollment{Secret: key.Secret(), URL: key.URL(), ExpiresAt: deadline}
		return nil
	})
	if err != nil {
		return Enrollment{}, err
	}
	return result, nil
}

// confirmation activates the secret only after possession is proved, else revoke every other session of this user including the curernt one as well
func (s *Service) ConfirmEnable2FA(ctx context.Context, token, code string) error {
	return s.transact(ctx, func(tx *sql.Tx) error {
		now := s.now()
		u, _, err := sessionUser(ctx, tx, token, now)
		if err != nil {
			return err
		}
		if u.MFAEnabled {
			return ErrAlreadyEnabled
		}
		if u.locked(now) {
			return ErrLocked
		}
		hash := secure.TokenHash(token)
		var encrypted []byte
		var expiry int64
		err = tx.QueryRowContext(ctx, "SELECT secret,expires_at FROM mfa_enrollments WHERE session_hash=?", hash).Scan(&encrypted, &expiry)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrEnrollment
		}
		if err != nil {
			return err
		}
		if now.UnixNano() >= expiry {
			return ErrEnrollment
		}
		secret, err := s.vault.Open(encrypted, "enrollment:"+hash)
		if err != nil {
			return fmt.Errorf("decrypt enrollment: %w", err)
		}
		defer clear(secret)
		step, valid := secure.MatchTOTP(string(secret), code, now, -1)
		if !valid {
			return s.fail(ctx, tx, &u, now)
		}
		active := s.vault.Seal(secret, totpPurpose(u.ID))
		if _, err := tx.ExecContext(ctx, `UPDATE users SET totp_secret=?,last_totp_step=?,failed_attempts=0,locked_until=NULL WHERE id=?`, active, step, u.ID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM sessions WHERE user_id=?", u.ID)
		return err
	})
}

func (s *Service) CancelEnrollment(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM mfa_enrollments WHERE session_hash=?", secure.TokenHash(token))
	return err
}

func (s *Service) Disable2FA(ctx context.Context, token string, password []byte, code string) error {
	return s.transact(ctx, func(tx *sql.Tx) error {
		u, expires, err := sessionUser(ctx, tx, token, s.now())
		if err != nil {
			return err
		}
		if !u.MFAEnabled {
			return ErrNotEnabled
		}
		if err := s.checkPassword(ctx, tx, &u, password); err != nil {
			return err
		}
		if !s.now().Before(expires) {
			return ErrSession
		}
		if _, err := s.checkCode(ctx, tx, &u, code, s.now()); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET totp_secret=NULL,last_totp_step=-1,failed_attempts=0,locked_until=NULL WHERE id=?`, u.ID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM sessions WHERE user_id=?", u.ID)
		return err
	})
}

func (s *Service) checkPassword(ctx context.Context, tx *sql.Tx, u *dbUser, password []byte) error {
	valid := s.passwords.Verify(u.passwordHash, password)
	now := s.now()
	if u.locked(now) {
		return ErrLocked
	}
	if !valid {
		return s.fail(ctx, tx, u, now)
	}
	return nil
}

func (s *Service) checkCode(ctx context.Context, tx *sql.Tx, u *dbUser, code string, now time.Time) (int64, error) {
	secret, err := s.vault.Open(u.secret, totpPurpose(u.ID))
	if err != nil {
		return 0, fmt.Errorf("decrypt MFA secret: %w", err)
	}
	defer clear(secret)
	step, valid := secure.MatchTOTP(string(secret), code, now, u.lastStep)
	if !valid {
		return 0, s.fail(ctx, tx, u, now)
	}
	return step, nil
}

func totpPurpose(id int64) string { return fmt.Sprintf("totp:user:%d", id) }

type committedDenial struct{ cause error }

func (e *committedDenial) Error() string { return e.cause.Error() }
func (e *committedDenial) Unwrap() error { return e.cause }

func (s *Service) fail(ctx context.Context, tx *sql.Tx, u *dbUser, now time.Time) error {
	attempts := u.failedAttempts
	if u.lockedUntil.Valid && now.UnixNano() >= u.lockedUntil.Int64 {
		attempts = 0
	}
	attempts++
	var lockedUntil any
	cause := ErrAuthentication
	if attempts >= s.cfg.MaxAttempts {
		lockedUntil = now.Add(s.cfg.LockoutDuration).UnixNano()
		cause = ErrLocked
	}
	_, err := tx.ExecContext(ctx, "UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?", attempts, lockedUntil, u.ID)
	if err != nil {
		return err
	}
	return &committedDenial{cause: cause}
}

func (s *Service) transact(ctx context.Context, action func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result := action(tx)
	var denial *committedDenial
	if result != nil && !errors.As(result, &denial) {
		return result
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return result
}
