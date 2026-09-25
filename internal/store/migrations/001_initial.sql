CREATE TABLE metadata (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_login_at INTEGER,
    totp_secret BLOB,
    last_totp_step INTEGER NOT NULL DEFAULT -1 CHECK (last_totp_step >= -1),
    failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    locked_until INTEGER
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY CHECK (length(token_hash) = 64),
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at)
);
CREATE INDEX sessions_user_id ON sessions(user_id);
CREATE INDEX sessions_expires_at ON sessions(expires_at);

CREATE TABLE mfa_enrollments (
    session_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE,
    secret BLOB NOT NULL,
    expires_at INTEGER NOT NULL
);
