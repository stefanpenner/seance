package tui

import "github.com/charmbracelet/bubbles/key"

type keyMap struct {
	Up        key.Binding
	Down      key.Binding
	New       key.Binding
	Kill      key.Binding
	Rename    key.Binding
	Help      key.Binding
	Quit      key.Binding
	Enter     key.Binding
	Escape    key.Binding
	Tab       key.Binding // switch focus between panes
	GoTop     key.Binding
	GoBottom  key.Binding
}

var keys = keyMap{
	Up: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("k/↑", "up"),
	),
	Down: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("j/↓", "down"),
	),
	New: key.NewBinding(
		key.WithKeys("n"),
		key.WithHelp("n", "new"),
	),
	Kill: key.NewBinding(
		key.WithKeys("d"),
		key.WithHelp("d", "kill"),
	),
	Rename: key.NewBinding(
		key.WithKeys("r"),
		key.WithHelp("r", "rename"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "help"),
	),
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
	Enter: key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("enter", "confirm"),
	),
	Escape: key.NewBinding(
		key.WithKeys("esc"),
		key.WithHelp("esc", "cancel"),
	),
	Tab: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "switch pane"),
	),
	GoTop: key.NewBinding(
		key.WithKeys("g"),
		key.WithHelp("gg", "top"),
	),
	GoBottom: key.NewBinding(
		key.WithKeys("G"),
		key.WithHelp("GG", "bottom"),
	),
}

func shortHelp() string {
	return "↑↓ nav • n new • d kill • r rename • tab log • gg/GG top/bottom • q quit"
}
