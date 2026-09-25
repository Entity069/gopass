# Verification record

Verified on 2026-09-25 using Go 1.27.1 on Linux, Docker 29.8.0, and
Docker Compose 5.5.1. All checks below passed.

| Check | Result |
| --- | --- |
| `make check` | Formatting, `go vet`, race tests and module checksum verification passed. |
| `go test -json ./...` | 111 passing test/subtest results; zero failures. |
| `go test -coverprofile=coverage.out ./...` | 81.8% overall statement coverage; 92.2% for authentication. |
| `make smoke` | Actual PTY registration, login, MFA, history/completion, persistence, expiry, lockout, interrupts and cleanup passed. |
| Race-instrumented binary + PTY suite | Same terminal workflow passed with `go build -race`. |
| Three fuzz targets, 10 seconds each, two workers | Password-hash parsing, TOTP input/time handling and username normalization passed. |
| Docker `test` stage | `go vet` and all race tests passed inside the build container. |
| Docker runtime build | Static binary in `scratch`, UID/GID `10001:10001`. |
| `python3 scripts/smoke.py --docker` | Full interactive workflow passed; accounts persisted across freshly created containers sharing the test volume. |
| `docker compose config --quiet` | Compose configuration valid. |
| `govulncheck` | Zero vulnerabilities affecting imported packages or reachable application code. |

The vulnerability scanner also reports module-level advisory
[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) for the unmaintained
`golang.org/x/crypto/openpgp` package. This application does not import OpenPGP;
it uses `golang.org/x/crypto/argon2`. The scanner identifies no affected application
code. Results are a point-in-time check, not a security audit or a guarantee
against unknown vulnerabilities.

Coverage above is from Go unit/integration tests. Separate PTY tests exercise
the terminal adapter and startup paths without contributing to that coverage
percentage. No reduced password hashing parameters are used in tests.

The default Docker daemon was unavailable in the verification environment, so
Docker checks used an isolated rootless daemon. Its bridge was disabled; image
builds used `--network=host` for dependency downloads. The application containers
still used the committed Compose configuration's `network_mode: none`. Disposable
test volumes were removed after each suite. No project data or Git commits were
created by those tests.

To repeat the checks, see the commands in [README.md](../README.md#tests-and-verification).
