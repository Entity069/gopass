package store

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestMigrationsPersistenceAndKeyBinding(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db with ? and #.sqlite")
	db, err := Open(ctx, path, "key-one")
	if err != nil {
		t.Fatal(err)
	}
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 1 {
		t.Fatal("migration missing", err)
	}
	for _, pragma := range []string{"foreign_keys", "secure_delete"} {
		var enabled int
		if err := db.QueryRow("PRAGMA " + pragma).Scan(&enabled); err != nil || enabled != 1 {
			t.Fatal("pragma not enabled", pragma, err)
		}
	}
	var mode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Fatal("WAL not enabled", err)
	}
	if _, err := db.Exec("INSERT INTO users(username,password_hash,created_at) VALUES('alice','hash',1)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(ctx, path, "key-one")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM users").Scan(&n); err != nil || n != 1 {
		t.Fatal("data lost on reopening", err)
	}
	if wrong, err := Open(ctx, path, "key-two"); err == nil {
		wrong.Close()
		t.Fatal("wrong key accepted")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe database permissions", err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		info, err := os.Stat(path + suffix)
		if err != nil || info.Mode().Perm()&0077 != 0 {
			t.Fatal("unsafe sidecar permissions", suffix, err)
		}
	}
}

func TestSchemaConstraintsAndCascade(t *testing.T) {
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "login.db"), "key")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, query := range []string{
		"INSERT INTO users(id,username,password_hash,created_at) VALUES(1,'alice','hash',1)",
		"INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1,1,2)",
		"INSERT INTO mfa_enrollments(session_hash,secret,expires_at) VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',x'01',2)",
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	for _, query := range []string{
		"INSERT INTO users(username,password_hash,created_at) VALUES('ALICE','hash',1)",
		"UPDATE users SET failed_attempts=-1",
		"UPDATE users SET last_totp_step=-2",
		"UPDATE sessions SET user_id=999",
		"UPDATE sessions SET token_hash='short'",
		"UPDATE sessions SET expires_at=created_at",
	} {
		if _, err := db.Exec(query); err == nil {
			t.Fatalf("constraint missing: %s", query)
		}
	}
	if _, err := db.Exec("DELETE FROM users"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"sessions", "mfa_enrollments"} {
		var n int
		if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatal("cascade failed", table, err)
		}
	}
}

func TestUnsafeOrUnsupportedDatabase(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "login.db")
	if err := os.WriteFile(path, []byte("not sqlite"), 0600); err != nil {
		t.Fatal(err)
	}
	if db, err := Open(ctx, path, "key"); err == nil {
		db.Close()
		t.Fatal("corrupt database accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if db, err := Open(ctx, path, "key"); err == nil {
		db.Close()
		t.Fatal("public database accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if db, err := Open(ctx, link, "key"); err == nil {
		db.Close()
		t.Fatal("symlink database accepted")
	}
	if db, err := Open(ctx, dir, "key"); err == nil {
		db.Close()
		t.Fatal("directory database accepted")
	}
	future := filepath.Join(dir, "future.db")
	db, err := Open(ctx, future, "key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA user_version=999"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if db, err := Open(ctx, future, "key"); err == nil {
		db.Close()
		t.Fatal("future schema accepted")
	}
}

func TestConcurrentInitialization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "login.db")
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Go(func() {
			db, err := Open(context.Background(), path, "key")
			if err != nil {
				t.Error(err)
				return
			}
			db.Close()
		})
	}
	wg.Wait()
}
