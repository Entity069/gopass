package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

func Open(ctx context.Context, path, keyID string) (*sql.DB, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err == nil {
		err = f.Close()
	}
	if err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("database must be a regular file with mode 0600")
	}
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "secure_delete(1)")

	q.Set("_txlock", "immediate")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := initialize(ctx, db, keyID); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func initialize(ctx context.Context, db *sql.DB, keyID string) error {
	if _, err := db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > 1 {
		return fmt.Errorf("database schema version %d is newer than this application supports", version)
	}
	if version == 0 {
		migration, err := migrations.ReadFile("migrations/001_initial.sql")
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(migration)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "PRAGMA user_version=1"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO metadata(name,value) VALUES('key_id',?)", keyID); err != nil {
			return err
		}
	}
	var storedID string
	if err := tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE name='key_id'").Scan(&storedID); err != nil {
		return err
	}
	if storedID != keyID {
		return errors.New("encryption key does not match the database; restore its original key")
	}
	return tx.Commit()
}
