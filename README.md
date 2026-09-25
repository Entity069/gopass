# Containerized CLI Login System

A Go command-line authentication system with registration, optional Google
Authenticator-compatible TOTP, persistent account lockouts, and expiring sessions.
Passwords and authenticator codes are entered in hidden prompts. The shell has
tab completion and in-memory command history.

## Run with Docker (recommended)

Prerequisites: Docker Engine or Docker Desktop running, with Docker Compose v2+.
Run these commands from this repository in a real terminal:

```sh
docker compose build
docker compose run --rm login
```

Use `docker compose run` for this interactive application. Do not use `-T`, pipe
credentials into stdin, or start it with `up -d`. `exit`, Ctrl+D, or Ctrl+C at the
command prompt ends the session and exits. Ctrl+C inside a form cancels that form.
External SIGTERM/SIGHUP also trigger terminal restoration and session cleanup.

The database is **SQLite, embedded in the Go process inside the container**. SQLite
does not need a separate database server. The Compose named volume `login-data`
holds `/data/login.db`, SQLite's WAL files, and `/data/master.key`. Removing or
recreating a CLI container preserves the volume. Run the command again to log in
with your existing account. No network connection is needed at runtime.

The runtime image uses `scratch`, runs as UID/GID `10001:10001`, has a read-only
root filesystem, no network, no Linux capabilities, and no privilege escalation.
Only the data volume is writable. Compose limits memory to 256 MiB and processes
to 64 where the Docker host supports those limits. Go and build tools remain in
the build stages.

Do not run `docker compose down --volumes` against data you want to retain: that
deletes the database **and** its encryption key. Plain `docker compose down`
preserves data. The smoke-test script uses its own unique project and deletes
only its disposable test volume.

## Run locally

Prerequisites: Go 1.27.1 or newer. SQLite is pure Go; no SQLite installation,
C compiler, or CGO is needed for the application build.

```sh
go mod download
make build
./bin/cli-login
# Alternatively:
go run ./cmd/login
```

Local data defaults to `./data`. The application creates it with mode `0700` and
the database/key with mode `0600`. An existing shared directory, symlink database,
or permissive key/database file is rejected. Use a dedicated private directory.
Credentials cannot be passed as process arguments. `./bin/cli-login --help` works
without a terminal; the interactive shell deliberately requires one so passwords
cannot accidentally be echoed by a noninteractive input path.

## Usage

| Before login | Action |
| --- | --- |
| `register` | Choose a username and enter/confirm a password. |
| `login` | Enter username/password, then a code if 2FA is enabled. |
| `help` | Show available commands and input hints. |
| `exit` | Quit. |

| After login | Action |
| --- | --- |
| `whoami` | Show username, registration date, MFA status, expiry, and last login. |
| `enable-2fa` | Reenter the password and confirm a code from a new authenticator. |
| `disable-2fa` | Reenter the password and a fresh code to remove MFA. |
| `logout` | Revoke this session and return to the login prompt. |
| `help` | Show authenticated commands. |
| `exit` | Revoke this session and quit. |

Commands take no arguments. Usernames are case-insensitive, canonicalized to
lowercase, and must be 3–32 characters: start with a letter, followed by letters,
digits, `.`, `_`, or `-`. Surrounding username whitespace is ignored.

Passwords must have at least **8 Unicode characters**, at most **1024 bytes**, no
control characters, and cannot consist only of whitespace. Long passphrases and
Unicode are supported; passwords are not trimmed, normalized, or truncated.
There are no mandatory character-class rules.

After a successful login, all requested account details appear automatically.
`Last login (before this session)` shows the previous successful login, or says
that this is the first login. `whoami` shows the most recent successful login.
All displayed dates and stored timestamps use UTC. Failed logins do not update
the last-login timestamp.

Only recognized commands without arguments enter history. Passwords, codes,
usernames entered in forms, setup keys, and unrecognized input are never saved
in command history. History is kept in memory for this process only. Use ↑/↓ to
navigate and Tab to complete commands available in the current login state.

### Enable and use 2FA

1. Register and log in, then enter `enable-2fa` and your current password.
2. In Google Authenticator, choose **Add a code → Enter a setup key**. Use the
   displayed account name and setup key; choose **Time based**. An `otpauth://`
   provisioning URI is also displayed for compatible tools. No online QR service
   receives the secret.
3. Enter the app's six-digit code. Setup expires after five minutes, or when the
   current session expires, whichever happens first. Cancelling or entering a
   wrong code leaves MFA disabled and cancels this CLI's pending setup.
4. Successful activation revokes **all** sessions for that user. Wait for the
   authenticator to show a **new code**, then `login` again. The confirmation code
   has already been used and cannot also log in.
5. To remove MFA, use `disable-2fa`, the current password, and a fresh code. This
   also revokes all sessions, requiring a new password-only login.

Keep the phone's clock synchronized. Codes use HMAC-SHA-1, six digits, and 30-second
periods, with one neighboring period allowed on each side. Codes are accepted
only once, including across concurrent processes and restarts. If a future-period
code is accepted, subsequent authentication must use a later period.

There is intentionally **no recovery bypass or password-reset command** in this
assignment. Losing the authenticator without retaining its setup key can lock you
out. Store that key securely if recovery is needed. The setup key and URI are
sensitive and appear in terminal scrollback; avoid screen recording or sharing
the terminal during enrollment. A production recovery workflow would need its
own authenticated identity-verification design.

## Configuration

For Compose, copy `.env.example` to `.env` and edit it, or export the listed policy
variables before launching. For local runs, export the variables directly; the
binary does not parse `.env` files.

| Variable | Default | Validation / purpose |
| --- | --- | --- |
| `APP_DATA_DIR` | `./data` locally; `/data` in Docker | Private storage directory. Compose fixes this at the volume mount. |
| `APP_KEY_FILE` | `<APP_DATA_DIR>/master.key` | File containing exactly 32 **raw binary bytes**, private permissions. |
| `APP_SESSION_TTL` | `30m` | Absolute session lifetime, `1s`–`24h`. Activity does not extend it. |
| `APP_MAX_ATTEMPTS` | `5` | Consecutive failed attempts before account lockout, `1`–`20`. |
| `APP_LOCKOUT_DURATION` | `15m` | Temporary lockout duration, `1s`–`24h`. |
| `APP_ISSUER` | `CLI Login` | Authenticator issuer, 1–64 bytes; no colons/control characters. |

Examples:

```sh
APP_SESSION_TTL=10m APP_MAX_ATTEMPTS=3 docker compose run --rm login
APP_DATA_DIR=./private-data APP_SESSION_TTL=5m go run ./cmd/login
```

Invalid or empty policy values fail at startup. Every running process sharing a
database should use the same lockout policy. Expiry is persisted when a session
is created; changing the TTL affects new sessions. Attempts made during an active
lockout do not extend it. After lockout expiration, a wrong attempt starts a new
failure count; a full successful authentication clears failures.

## Security design

- **Passwords:** Argon2id with 64 MiB memory, three iterations, two lanes, a random
  128-bit salt per password, and a 256-bit output. PHC-formatted hashes use strict,
  bounded parsing and constant-time output comparison. Unknown users perform a
  dummy password verification. See [OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- **TOTP secrets:** AES-256-GCM authenticated encryption with fresh random nonces.
  Additional authenticated data binds active secrets to user IDs and pending
  secrets to enrollment sessions, preventing ciphertext substitution. The AES
  key is generated from `crypto/rand`, atomically published, and persisted. A key
  fingerprint binds the database to its original key. Missing or wrong keys for
  existing databases fail closed instead of silently replacing them.
- **MFA transitions:** Enrollment requires password reauthentication and proof of
  possession. Disabling requires the password and an unused existing factor.
  Success revokes all user sessions atomically. Failed password/code checks share
  account lockout counters; requesting a new enrollment or passing only the
  password stage does not clear MFA failures. See [OWASP MFA guidance](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html).
- **Replay and concurrency:** `BEGIN IMMEDIATE` transactions serialize security
  decisions across SQLite connections/processes. Successful TOTP steps, session
  creation, last-login updates, and failure resets commit together. Denied
  authentication commits its failure counter. SQL errors roll back the operation.
  The consumed time step persists, following [RFC 6238 replay guidance](https://www.rfc-editor.org/rfc/rfc6238.html).
- **Sessions:** 256-bit cryptographically random bearer tokens, held only in
  process memory. The database stores SHA-256 token digests, never raw tokens.
  Every protected operation checks persisted expiry/revocation. Logout and clean
  exit delete the session; stale rows from crashes expire and are pruned on a
  later successful login. See [OWASP session guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).
- **Storage/input:** Parameterized SQL, database constraints, foreign-key cascades,
  automatic transactional migration, private file permissions, WAL mode and a
  five-second SQLite busy timeout. Authentication failures use the same visible
  message for bad passwords, bad codes, unknown users and temporary lockouts.
  Registration necessarily reports a duplicate username.

## Persistence, schema and backups

The embedded migration is
[`internal/store/migrations/001_initial.sql`](internal/store/migrations/001_initial.sql).
It creates `users`, `sessions`, `mfa_enrollments`, and key-binding `metadata`.
Schema version is tracked with SQLite `PRAGMA user_version`; newer unsupported
schemas are rejected. Startup migration is automatic and safe to repeat.

For a consistent file-level backup, **stop every CLI process/container using the
volume**, then back up the entire data directory, including the key and any WAL
files. Restore into a private directory/volume with the original ownership and
permissions. Never copy only the main `.db` file from a running WAL database.
This assignment does not implement encryption-key rotation.

## Tests and verification

Recorded results are in [docs/VERIFICATION.md](docs/VERIFICATION.md), including
the executed Docker and real-terminal checks, coverage, and vulnerability scan.

```sh
make check                 # Formatting, go vet, all tests with race detector, module checksums
make coverage              # Statement coverage report
make smoke                 # Build and exercise the actual CLI through a pseudo-terminal
make docker-test           # Run vet + race tests in the Docker build environment
docker compose build
python3 scripts/smoke.py --docker  # Same terminal suite against fresh Compose containers
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

The race detector needs CGO and a C compiler locally. Docker's `test` stage
includes both. Smoke tests need Python 3 and Linux/macOS PTY support, with no pip
dependencies. They calculate TOTP independently of the Go library and may wait
up to 30 seconds for a real authenticator time step. All test accounts/data are
temporary. Docker smoke tests verify persistence by reopening the same disposable
named volume in fresh containers, then remove that test volume.

Coverage includes successful and rejected registration; username/password
boundaries, Unicode and injection input; PHC hash corruption; encryption
tampering, owner binding and key permissions; RFC TOTP vectors, time skew,
malformed codes and replay; exact session and lockout deadlines; retries and
resets; failed/cancelled/expired enrollment; authenticated MFA changes;
transaction rollback; concurrent registrations, lockouts and duplicate TOTP
attempts across independent connections; persistence; migration idempotence;
schema constraints; terminal help/history/completion; hidden passwords; logout,
EOF and interrupt handling. Tests use real SQLite files and real production
Argon2id parameters.