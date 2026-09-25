package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/osto-assignment/cli-login/internal/auth"
	"github.com/osto-assignment/cli-login/internal/cli"
	"github.com/osto-assignment/cli-login/internal/config"
	"github.com/osto-assignment/cli-login/internal/secure"
	"github.com/osto-assignment/cli-login/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 {
		if len(os.Args) == 2 && (os.Args[1] == "--help" || os.Args[1] == "-h") {
			fmt.Println("Usage: cli-login\nStart the interactive login shell. Type help inside the shell.\nConfiguration: APP_DATA_DIR, APP_KEY_FILE, APP_SESSION_TTL, APP_MAX_ATTEMPTS, APP_LOCKOUT_DURATION, APP_ISSUER.\nSee README.md for defaults and setup.")
			return nil
		}
		return errors.New("this program accepts no credentials or commands as arguments; use --help")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	terminal, err := cli.NewTerminal()
	if err != nil {
		return err
	}
	defer terminal.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	go func() { <-ctx.Done(); terminal.Close() }()
	if err := secure.PrivateDir(cfg.DataDir); err != nil {
		return err
	}
	database := filepath.Join(cfg.DataDir, "login.db")
	_, statErr := os.Lstat(database)
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	key, err := secure.LoadKey(cfg.KeyFile, errors.Is(statErr, os.ErrNotExist))
	if err != nil {
		return err
	}
	vault, err := secure.NewVault(key)
	clear(key)
	if err != nil {
		return err
	}
	db, err := store.Open(ctx, database, vault.ID())
	if err != nil {
		return err
	}
	defer db.Close()
	service, err := auth.New(db, vault, cfg)
	if err != nil {
		return err
	}
	return cli.New(service, terminal).Run(ctx)
}
