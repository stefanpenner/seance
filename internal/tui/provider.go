package tui

import "seance/internal/session"

// SessionProvider abstracts session management so the TUI can work
// with either a local in-process Manager or a remote HTTP API.
type SessionProvider interface {
	List() ([]session.Info, error)
	Create(name, shell string, cols, rows uint16, env []string, parentID string) (session.Info, error)
	Kill(id string) error
	Rename(id string, name string) error
	ServerURL() string
}
