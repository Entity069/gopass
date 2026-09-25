package cli

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/chzyer/readline"
	"golang.org/x/term"
)

var guestCommands = []string{"register", "login", "help", "exit"}
var memberCommands = []string{"whoami", "enable-2fa", "disable-2fa", "logout", "help", "exit"}

type Console interface {
	Command(loggedIn bool) (string, error)
	Input(prompt string) (string, error)
	Secret(prompt string) ([]byte, error)
	Remember(command string) error
	Printf(format string, args ...any)
}

type Terminal struct {
	line *readline.Instance
	once sync.Once
}

func NewTerminal() (*Terminal, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return nil, errors.New("an interactive terminal is required; use docker compose run --rm login (without -T), or run the binary in a terminal")
	}
	line, err := readline.NewEx(&readline.Config{
		Prompt: "login> ", HistoryLimit: 100, DisableAutoSaveHistory: true,
		InterruptPrompt: "^C", EOFPrompt: "exit",
	})
	if err != nil {
		return nil, err
	}
	return &Terminal{line: line}, nil
}

func (t *Terminal) Close() { t.once.Do(func() { _ = t.line.Close() }) }

func (t *Terminal) Command(loggedIn bool) (string, error) {
	commands, prompt := guestCommands, "login> "
	if loggedIn {
		commands, prompt = memberCommands, "account> "
	}

	cfg := *t.line.Config
	cfg.Prompt = prompt
	items := make([]readline.PrefixCompleterInterface, 0, len(commands))
	for _, command := range commands {
		items = append(items, readline.PcItem(command))
	}
	cfg.AutoComplete = readline.NewPrefixCompleter(items...)
	t.line.SetConfig(&cfg)
	return t.line.Readline()
}

func (t *Terminal) Input(prompt string) (string, error) {
	cfg := t.line.Config.Clone()
	cfg.Prompt = prompt
	cfg.AutoComplete = nil
	cfg.HistoryLimit = -1
	previous := t.line.SetConfig(cfg)
	defer t.line.SetConfig(previous)
	return t.line.Readline()
}

func (t *Terminal) Secret(prompt string) ([]byte, error) { return t.line.ReadPassword(prompt) }
func (t *Terminal) Remember(command string) error        { return t.line.SaveHistory(command) }
func (t *Terminal) Printf(format string, args ...any)    { fmt.Fprintf(t.line.Stdout(), format, args...) }
