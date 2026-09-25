package main

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/term"
)

func withArgs(t *testing.T, args ...string) {
	t.Helper()
	original := os.Args
	os.Args = append([]string{"cli-login"}, args...)
	t.Cleanup(func() { os.Args = original })
}

func TestHelpDoesNotRequireTerminalOrValidConfig(t *testing.T) {
	withArgs(t, "--help")
	t.Setenv("APP_SESSION_TTL", "invalid")
	if err := run(); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialsAreNeverAcceptedAsArguments(t *testing.T) {
	withArgs(t, "login", "alice", "not-a-real-password")
	err := run()
	if err == nil || strings.Contains(err.Error(), "not-a-real-password") {
		t.Fatal("arguments accepted or leaked", err)
	}
}

func TestInvalidConfigurationFailsBeforeStartup(t *testing.T) {
	withArgs(t)
	t.Setenv("APP_SESSION_TTL", "0s")
	if err := run(); err == nil || !strings.Contains(err.Error(), "APP_SESSION_TTL") {
		t.Fatal("unsafe configuration accepted", err)
	}
}

func TestNonTTYFailsBeforeCreatingData(t *testing.T) {
	if term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) {
		t.Skip("requires redirected test input or output")
	}
	withArgs(t)
	path := t.TempDir() + "/data"
	t.Setenv("APP_DATA_DIR", path)
	t.Setenv("APP_SESSION_TTL", "30m")
	if err := run(); err == nil || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatal("non-TTY input accepted", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("non-TTY startup mutated storage", err)
	}
}
