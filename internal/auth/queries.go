package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/osto-assignment/cli-login/internal/secure"
)

type dbUser struct {
	User
	passwordHash   string
	secret         []byte
	lastStep       int64
	failedAttempts int
	lockedUntil    sql.NullInt64
}

const userColumns = "u.id,u.username,u.password_hash,u.created_at,u.last_login_at,u.totp_secret,u.last_totp_step,u.failed_attempts,u.locked_until"

func (u dbUser) locked(now time.Time) bool {
	return u.lockedUntil.Valid && now.UnixNano() < u.lockedUntil.Int64
}

func scanUser(row *sql.Row, expiry *int64) (dbUser, error) {
	var u dbUser
	var created int64
	var last sql.NullInt64
	fields := []any{&u.ID, &u.Username, &u.passwordHash, &created, &last, &u.secret, &u.lastStep, &u.failedAttempts, &u.lockedUntil}
	if expiry != nil {
		fields = append(fields, expiry)
	}
	if err := row.Scan(fields...); err != nil {
		return u, err
	}
	u.RegisteredAt = time.Unix(0, created).UTC()
	if last.Valid {
		value := time.Unix(0, last.Int64).UTC()
		u.LastLoginAt = &value
	}
	u.MFAEnabled = len(u.secret) > 0
	return u, nil
}

func userByName(ctx context.Context, tx *sql.Tx, username string) (dbUser, error) {
	return scanUser(tx.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users u WHERE u.username=?", username), nil)
}

func sessionUser(ctx context.Context, tx *sql.Tx, token string, now time.Time) (dbUser, time.Time, error) {
	if !secure.ValidToken(token) {
		return dbUser{}, time.Time{}, ErrSession
	}
	var expiry int64
	u, err := scanUser(tx.QueryRowContext(ctx, "SELECT "+userColumns+",s.expires_at FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token_hash=? AND s.expires_at>?", secure.TokenHash(token), now.UnixNano()), &expiry)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrSession
	}
	return u, time.Unix(0, expiry).UTC(), err
}
