package tui

import "github.com/charmbracelet/lipgloss"

// Tokyonight color palette
var (
	colorBg        = lipgloss.Color("#1a1b26")
	colorBgFloat   = lipgloss.Color("#1f2335")
	colorBgHL      = lipgloss.Color("#292e42")
	colorSelection = lipgloss.Color("#283457")
	colorBorder    = lipgloss.Color("#29334d")
	colorFg        = lipgloss.Color("#c0caf5")
	colorFgDark    = lipgloss.Color("#a9b1d6")
	colorGutter    = lipgloss.Color("#3b4261")
	colorComment   = lipgloss.Color("#565f89")
	colorBlue      = lipgloss.Color("#7aa2f7")
	colorCyan      = lipgloss.Color("#7dcfff")
	colorGreen     = lipgloss.Color("#9ece6a")
	colorMagenta   = lipgloss.Color("#bb9af7")
	colorRed       = lipgloss.Color("#f7768e")
	colorYellow    = lipgloss.Color("#e0af68")
)

var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorMagenta)

	borderStyle = lipgloss.NewStyle().
			Foreground(colorBorder)

	separatorStyle = lipgloss.NewStyle().
			Foreground(colorGutter)

	selectedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorBlue).
			Background(colorSelection)

	normalStyle = lipgloss.NewStyle().
			Foreground(colorFg)

	dimStyle = lipgloss.NewStyle().
			Foreground(colorComment)

	errorStyle = lipgloss.NewStyle().
			Foreground(colorRed)

	successStyle = lipgloss.NewStyle().
			Foreground(colorGreen)

	labelStyle = lipgloss.NewStyle().
			Foreground(colorComment).
			Width(10)

	valueStyle = lipgloss.NewStyle().
			Foreground(colorFg)

	footerStyle = lipgloss.NewStyle().
			Foreground(colorGutter)

	logTitleStyle = lipgloss.NewStyle().
			Foreground(colorComment).
			Bold(true)

	logLineStyle = lipgloss.NewStyle().
			Foreground(colorComment)

	urlStyle = lipgloss.NewStyle().
			Foreground(colorCyan)
)
