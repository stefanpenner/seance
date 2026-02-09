package tui

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"seance/internal/session"
)

const horizontalPad = 1

type mode int

const (
	modeNormal mode = iota
	modeConfirmKill
	modeRename
)

type pane int

const (
	paneSessions pane = iota
	paneLogs
)

// LogLine is a single server log entry sent to the TUI.
type LogLine string

// LogWriter is an io.Writer that sends log lines to the TUI program.
type LogWriter struct {
	mu      sync.Mutex
	program *tea.Program
	buf     []byte
}

func NewLogWriter() *LogWriter {
	return &LogWriter{}
}

func (w *LogWriter) SetProgram(p *tea.Program) {
	w.mu.Lock()
	w.program = p
	w.mu.Unlock()
}

func (w *LogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	prog := w.program
	w.mu.Unlock()

	w.buf = append(w.buf, p...)
	for {
		idx := -1
		for i, b := range w.buf {
			if b == '\n' {
				idx = i
				break
			}
		}
		if idx < 0 {
			break
		}
		line := string(w.buf[:idx])
		w.buf = w.buf[idx+1:]
		if prog != nil {
			prog.Send(LogLine(line))
		}
	}
	return len(p), nil
}

type Model struct {
	mgr      *session.Manager
	shell    string
	childEnv []string
	sessions []session.Info
	cursor   int
	width    int
	height   int
	err      error
	loading  bool
	mode     mode

	confirmID string
	renameID  string
	input     textinput.Model

	logLines  []string
	logMax    int
	logScroll int // scroll offset for log pane (0 = bottom)
	focus     pane

	serverURL string

	// Vim gg/GG
	pendingG  bool
	pendingGG bool
}

type sessionsMsg []session.Info
type errMsg struct{ err error }
type tickMsg time.Time

func (e errMsg) Error() string { return e.err.Error() }

func NewModel(mgr *session.Manager, shell string, childEnv []string) Model {
	ti := textinput.New()
	ti.CharLimit = 64
	return Model{
		mgr:      mgr,
		shell:    shell,
		childEnv: childEnv,
		loading:  true,
		input:    ti,
		logMax:   500,
		focus:    paneSessions,
	}
}

// SetServerURL sets the URL shown in the TUI header.
func (m *Model) SetServerURL(url string) {
	m.serverURL = url
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.fetchSessions(), tickCmd())
}

func tickCmd() tea.Cmd {
	return tea.Tick(3*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m Model) fetchSessions() tea.Cmd {
	return func() tea.Msg {
		return sessionsMsg(m.mgr.List())
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case sessionsMsg:
		m.sessions = msg
		m.loading = false
		m.err = nil
		if m.cursor >= len(m.sessions) && len(m.sessions) > 0 {
			m.cursor = len(m.sessions) - 1
		}

	case errMsg:
		m.err = msg.err
		m.loading = false

	case LogLine:
		m.logLines = append(m.logLines, string(msg))
		if len(m.logLines) > m.logMax {
			m.logLines = m.logLines[len(m.logLines)-m.logMax:]
		}
		// Auto-scroll if at bottom
		if m.logScroll == 0 {
			// already at bottom, stay there
		}

	case tickMsg:
		return m, tea.Batch(m.fetchSessions(), tickCmd())

	case tea.KeyMsg:
		switch m.mode {
		case modeConfirmKill:
			return m.updateConfirmKill(msg)
		case modeRename:
			return m.updateRename(msg)
		default:
			return m.updateNormal(msg)
		}
	}
	return m, nil
}

func (m Model) updateNormal(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Tab switches focus
	if key.Matches(msg, keys.Tab) {
		if m.focus == paneSessions {
			m.focus = paneLogs
		} else {
			m.focus = paneSessions
		}
		m.pendingG = false
		m.pendingGG = false
		return m, nil
	}

	// Quit always works
	if key.Matches(msg, keys.Quit) {
		return m, tea.Quit
	}

	// Handle gg/GG sequences
	if key.Matches(msg, keys.GoTop) {
		if m.pendingG {
			m.pendingG = false
			if m.focus == paneSessions {
				m.cursor = 0
			} else {
				m.logScroll = max(0, len(m.logLines)-1)
			}
			return m, nil
		}
		m.pendingG = true
		m.pendingGG = false
		return m, nil
	}
	if key.Matches(msg, keys.GoBottom) {
		if m.pendingGG {
			m.pendingGG = false
			if m.focus == paneSessions {
				if len(m.sessions) > 0 {
					m.cursor = len(m.sessions) - 1
				}
			} else {
				m.logScroll = 0
			}
			return m, nil
		}
		m.pendingGG = true
		m.pendingG = false
		return m, nil
	}
	m.pendingG = false
	m.pendingGG = false

	if m.focus == paneLogs {
		return m.updateLogPane(msg)
	}

	switch {
	case key.Matches(msg, keys.Up):
		if m.cursor > 0 {
			m.cursor--
		}

	case key.Matches(msg, keys.Down):
		if m.cursor < len(m.sessions)-1 {
			m.cursor++
		}

	case key.Matches(msg, keys.New):
		return m, func() tea.Msg {
			_, err := m.mgr.Create("", m.shell, 80, 24, m.childEnv, "")
			if err != nil {
				return errMsg{err}
			}
			return sessionsMsg(m.mgr.List())
		}

	case key.Matches(msg, keys.Kill):
		if len(m.sessions) > 0 {
			m.mode = modeConfirmKill
			m.confirmID = m.sessions[m.cursor].ID
		}

	case key.Matches(msg, keys.Rename):
		if len(m.sessions) > 0 {
			m.mode = modeRename
			m.renameID = m.sessions[m.cursor].ID
			m.input.SetValue(m.sessions[m.cursor].Name)
			m.input.Focus()
			return m, m.input.Cursor.BlinkCmd()
		}
	}
	return m, nil
}

func (m Model) updateLogPane(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, keys.Up):
		m.logScroll++
	case key.Matches(msg, keys.Down):
		if m.logScroll > 0 {
			m.logScroll--
		}
	}
	return m, nil
}

func (m Model) updateConfirmKill(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, keys.Enter):
		id := m.confirmID
		m.mode = modeNormal
		m.confirmID = ""
		return m, func() tea.Msg {
			if err := m.mgr.Kill(id); err != nil {
				return errMsg{err}
			}
			return sessionsMsg(m.mgr.List())
		}

	case key.Matches(msg, keys.Escape), key.Matches(msg, keys.Quit):
		m.mode = modeNormal
		m.confirmID = ""
	}
	return m, nil
}

func (m Model) updateRename(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, keys.Enter):
		id := m.renameID
		name := m.input.Value()
		m.mode = modeNormal
		m.renameID = ""
		m.input.Blur()
		return m, func() tea.Msg {
			if err := m.mgr.Rename(id, name); err != nil {
				return errMsg{err}
			}
			return sessionsMsg(m.mgr.List())
		}

	case key.Matches(msg, keys.Escape):
		m.mode = modeNormal
		m.renameID = ""
		m.input.Blur()
		return m, nil
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m Model) View() string {
	if m.width == 0 {
		return "Loading..."
	}

	// Sort sessions: parents by created_at, children immediately after their parent
	m.sessions = treeSort(m.sessions)

	width := m.width
	if width < 40 {
		width = 40
	}
	totalWidth := width - horizontalPad*2

	// Layout:
	// 1 line: header (URL + title)
	// 1 line: top border
	// N lines: content (sessions left + details right)
	// 1 line: mid border
	// M lines: log pane
	// 1 line: bottom border
	// 1 line: footer

	headerLines := 2 // header + top border
	footerLines := 2 // bottom border + footer
	logHeight := m.height / 4
	if logHeight < 4 {
		logHeight = 4
	}
	if logHeight > 16 {
		logHeight = 16
	}
	contentHeight := m.height - headerLines - footerLines - logHeight - 1 // 1 for mid border
	if contentHeight < 4 {
		contentHeight = 4
	}

	leftWidth := totalWidth * 2 / 5
	if leftWidth < 28 {
		leftWidth = 28
	}
	rightWidth := totalWidth - leftWidth - 1 // 1 for separator

	var b strings.Builder

	// Header line
	b.WriteString(m.renderHeader(totalWidth))
	b.WriteString("\n")

	// Top border
	b.WriteString(borderStyle.Render("╭" + strings.Repeat("─", leftWidth) + "┬" + strings.Repeat("─", rightWidth) + "╮"))
	b.WriteString("\n")

	// Content: sessions list + details
	leftLines := m.renderListLines(leftWidth, contentHeight)
	rightLines := m.renderDetailLines(rightWidth, contentHeight)

	for i := 0; i < contentHeight; i++ {
		left := ""
		if i < len(leftLines) {
			left = leftLines[i]
		}
		right := ""
		if i < len(rightLines) {
			right = rightLines[i]
		}
		b.WriteString(borderStyle.Render("│"))
		b.WriteString(left)
		b.WriteString(separatorStyle.Render("│"))
		b.WriteString(right)
		b.WriteString(borderStyle.Render("│"))
		b.WriteString("\n")
	}

	// Mid border between content and logs
	focusIndicator := "─"
	if m.focus == paneLogs {
		focusIndicator = "═"
	}
	logBorder := strings.Repeat(focusIndicator, totalWidth-2)
	if m.focus == paneLogs {
		b.WriteString(borderStyle.Render("╞") + borderStyle.Render(logBorder) + borderStyle.Render("╡"))
	} else {
		b.WriteString(borderStyle.Render("├") + borderStyle.Render(strings.Repeat("─", totalWidth-2)) + borderStyle.Render("┤"))
	}
	b.WriteString("\n")

	// Log pane
	logLines := m.renderLogLines(totalWidth-2, logHeight)
	for _, line := range logLines {
		b.WriteString(borderStyle.Render("│"))
		b.WriteString(line)
		b.WriteString(borderStyle.Render("│"))
		b.WriteString("\n")
	}

	// Bottom border
	b.WriteString(borderStyle.Render("╰" + strings.Repeat("─", totalWidth-2) + "╯"))
	b.WriteString("\n")

	// Footer
	b.WriteString(m.renderFooter(totalWidth))

	return addPadding(b.String(), horizontalPad)
}

func (m Model) renderHeader(width int) string {
	title := headerStyle.Render("seance")
	url := ""
	if m.serverURL != "" {
		url = urlStyle.Render(m.serverURL)
	}
	count := dimStyle.Render(fmt.Sprintf("%d sessions", len(m.sessions)))

	// title + count on left, url on right
	leftPlain := fmt.Sprintf("seance  %d sessions", len(m.sessions))
	left := title + "  " + count
	rightPlain := m.serverURL

	gap := width - len(leftPlain) - len(rightPlain)
	if gap < 2 {
		gap = 2
	}

	return left + strings.Repeat(" ", gap) + url
}

func (m Model) renderListLines(width, height int) []string {
	lines := make([]string, 0, height)

	// Header
	focusChar := " "
	if m.focus == paneSessions {
		focusChar = "▸"
	}
	header := fmt.Sprintf("%s SESSIONS (%d)", focusChar, len(m.sessions))
	hdr := padLine(dimStyle.Render(header), width)
	lines = append(lines, hdr)

	sep := padLine(separatorStyle.Render(strings.Repeat("─", width-2)), width)
	lines = append(lines, sep)

	if len(m.sessions) == 0 {
		empty := padLine(dimStyle.Render(" no sessions"), width)
		lines = append(lines, empty)
		for len(lines) < height {
			lines = append(lines, strings.Repeat(" ", width))
		}
		return lines
	}

	// Calculate visible window with center-cursor scrolling
	availableRows := height - 2 // minus header and separator
	startIdx := 0
	if len(m.sessions) > availableRows {
		half := availableRows / 2
		startIdx = m.cursor - half
		if startIdx < 0 {
			startIdx = 0
		}
		if startIdx+availableRows > len(m.sessions) {
			startIdx = len(m.sessions) - availableRows
			if startIdx < 0 {
				startIdx = 0
			}
		}
	}

	endIdx := startIdx + availableRows
	if endIdx > len(m.sessions) {
		endIdx = len(m.sessions)
	}

	needsScroll := len(m.sessions) > availableRows

	for idx := startIdx; idx < endIdx; idx++ {
		s := m.sessions[idx]
		isSelected := idx == m.cursor

		cursor := "  "
		if isSelected {
			cursor = "▸ "
		}

		prefix := ""
		if s.ParentID != "" {
			prefix = "  └ "
		}

		name := prefix + s.Name
		maxName := width - 16
		if maxName < 8 {
			maxName = 8
		}
		if len(name) > maxName {
			name = name[:maxName-3] + "..."
		}

		status := successStyle.Render("●")
		suffix := ""
		if s.Exited {
			status = errorStyle.Render("✗")
			suffix = dimStyle.Render(fmt.Sprintf(" exit(%d)", s.ExitCode))
		} else if s.Viewers > 0 {
			suffix = dimStyle.Render(fmt.Sprintf(" %dv", s.Viewers))
		}

		var content string
		if isSelected {
			content = cursor + selectedStyle.Render(name) + " " + status + suffix
		} else {
			content = cursor + normalStyle.Render(name) + " " + status + suffix
		}

		scrollChar := ""
		if needsScroll {
			scrollChar = m.scrollbarChar(idx-startIdx, availableRows, len(m.sessions), startIdx)
		}

		line := padLine(content, width-lipgloss.Width(scrollChar)) + scrollChar
		lines = append(lines, line)
	}

	for len(lines) < height {
		lines = append(lines, strings.Repeat(" ", width))
	}
	return lines
}

func (m Model) scrollbarChar(row, viewHeight, totalItems, startIdx int) string {
	trackHeight := viewHeight * 80 / 100
	if trackHeight < 3 {
		trackHeight = min(3, viewHeight)
	}
	topPad := (viewHeight - trackHeight) / 2

	thumbSize := max(1, trackHeight*viewHeight/totalItems)
	if thumbSize > trackHeight {
		thumbSize = trackHeight
	}

	maxScroll := totalItems - viewHeight
	thumbStart := 0
	if maxScroll > 0 {
		thumbStart = startIdx * (trackHeight - thumbSize) / maxScroll
	}

	trackIdx := row - topPad
	if row < topPad || row >= viewHeight-(viewHeight-trackHeight-topPad) {
		return " "
	}
	if trackIdx >= thumbStart && trackIdx < thumbStart+thumbSize {
		return separatorStyle.Render("┃")
	}
	return separatorStyle.Render("│")
}

func (m Model) renderDetailLines(width, height int) []string {
	lines := make([]string, 0, height)

	if len(m.sessions) == 0 || m.cursor >= len(m.sessions) {
		empty := padLine(dimStyle.Render(" no session selected"), width)
		lines = append(lines, empty)
		for len(lines) < height {
			lines = append(lines, strings.Repeat(" ", width))
		}
		return lines
	}

	s := m.sessions[m.cursor]

	// Title
	title := padLine(" "+headerStyle.Render(s.Name), width)
	lines = append(lines, title)

	sep := padLine(" "+separatorStyle.Render(strings.Repeat("─", width-3)), width)
	lines = append(lines, sep)

	// Detail rows
	rows := []struct{ label, value string }{
		{"ID:", s.ID},
		{"Shell:", s.Shell},
		{"Created:", timeAgo(s.CreatedAt)},
		{"Size:", fmt.Sprintf("%d×%d", s.Cols, s.Rows)},
		{"Viewers:", fmt.Sprintf("%d", s.Viewers)},
	}
	if s.ParentID != "" {
		rows = append(rows, struct{ label, value string }{"Parent:", s.ParentID})
	}

	statusVal := successStyle.Render("running")
	if s.Exited {
		statusVal = errorStyle.Render(fmt.Sprintf("exited(%d)", s.ExitCode))
	}

	for _, r := range rows {
		line := " " + labelStyle.Render(r.label) + valueStyle.Render(r.value)
		lines = append(lines, padLine(line, width))
	}
	// Status row
	statusLine := " " + labelStyle.Render("Status:") + statusVal
	lines = append(lines, padLine(statusLine, width))

	// Confirm kill / rename prompts
	if m.mode == modeConfirmKill && m.confirmID == s.ID {
		lines = append(lines, padLine("", width))
		prompt := " " + errorStyle.Render("Kill? [enter] yes  [esc] no")
		lines = append(lines, padLine(prompt, width))
	}
	if m.mode == modeRename && m.renameID == s.ID {
		lines = append(lines, padLine("", width))
		rename := " Rename: " + m.input.View()
		lines = append(lines, padLine(rename, width))
	}

	for len(lines) < height {
		lines = append(lines, strings.Repeat(" ", width))
	}
	return lines
}

func (m Model) renderLogLines(width, height int) []string {
	lines := make([]string, 0, height)

	// Log header
	logTitle := " LOG"
	if m.focus == paneLogs {
		logTitle = "▸LOG"
	}
	hdr := padLine(logTitleStyle.Render(logTitle), width)
	lines = append(lines, hdr)

	// Visible log lines
	visibleLines := height - 1 // minus header
	if visibleLines < 1 {
		visibleLines = 1
	}

	// Calculate visible window with scroll offset
	// logScroll=0 means show bottom (latest), logScroll>0 means scrolled up
	totalLogs := len(m.logLines)
	endIdx := totalLogs - m.logScroll
	if endIdx < 0 {
		endIdx = 0
	}
	startIdx := endIdx - visibleLines
	if startIdx < 0 {
		startIdx = 0
	}

	// Clamp logScroll
	maxScroll := totalLogs - visibleLines
	if maxScroll < 0 {
		maxScroll = 0
	}
	if m.logScroll > maxScroll {
		m.logScroll = maxScroll
	}

	needsScroll := totalLogs > visibleLines

	for i := startIdx; i < endIdx; i++ {
		line := m.logLines[i]
		if len(line) > width-2 {
			line = line[:width-2]
		}
		content := " " + logLineStyle.Render(line)

		scrollChar := ""
		if needsScroll {
			row := i - startIdx
			scrollChar = m.logScrollChar(row, visibleLines, totalLogs, startIdx)
		}

		lines = append(lines, padLine(content, width-lipgloss.Width(scrollChar))+scrollChar)
	}

	// Fill empty rows
	for len(lines) < height {
		lines = append(lines, strings.Repeat(" ", width))
	}

	return lines
}

func (m Model) logScrollChar(row, viewHeight, totalItems, startIdx int) string {
	trackHeight := viewHeight * 80 / 100
	if trackHeight < 3 {
		trackHeight = min(3, viewHeight)
	}
	topPad := (viewHeight - trackHeight) / 2

	thumbSize := max(1, trackHeight*viewHeight/totalItems)
	if thumbSize > trackHeight {
		thumbSize = trackHeight
	}

	maxScroll := totalItems - viewHeight
	thumbStart := 0
	if maxScroll > 0 {
		thumbStart = startIdx * (trackHeight - thumbSize) / maxScroll
	}

	trackIdx := row - topPad
	if row < topPad || row >= viewHeight-(viewHeight-trackHeight-topPad) {
		return " "
	}
	if trackIdx >= thumbStart && trackIdx < thumbStart+thumbSize {
		return separatorStyle.Render("┃")
	}
	return separatorStyle.Render("│")
}

func (m Model) renderFooter(width int) string {
	help := shortHelp()
	helpWidth := lipgloss.Width(help)

	leftPad := (width - helpWidth) / 2
	if leftPad < 0 {
		leftPad = 0
	}

	var errText string
	if m.err != nil {
		errText = errorStyle.Render(" Error: "+m.err.Error()) + "  "
	}

	return errText + strings.Repeat(" ", leftPad) + footerStyle.Render(help)
}

func padLine(content string, targetWidth int) string {
	pad := targetWidth - lipgloss.Width(content)
	if pad < 0 {
		pad = 0
	}
	return content + strings.Repeat(" ", pad)
}

func addPadding(content string, pad int) string {
	lines := strings.Split(content, "\n")
	padStr := strings.Repeat(" ", pad)
	var result strings.Builder
	for i, line := range lines {
		result.WriteString(padStr)
		result.WriteString(line)
		if i < len(lines)-1 {
			result.WriteString("\n")
		}
	}
	return result.String()
}

// treeSort orders sessions as a tree: parents sorted by created_at,
// with children immediately after their parent, also sorted by created_at.
func treeSort(sessions []session.Info) []session.Info {
	sorted := make([]session.Info, len(sessions))
	copy(sorted, sessions)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].CreatedAt.Before(sorted[j].CreatedAt)
	})

	// Separate parents and children
	var parents []session.Info
	children := make(map[string][]session.Info) // parentID -> children
	for _, s := range sorted {
		if s.ParentID == "" {
			parents = append(parents, s)
		} else {
			children[s.ParentID] = append(children[s.ParentID], s)
		}
	}

	// Interleave: parent, then its children
	result := make([]session.Info, 0, len(sessions))
	for _, p := range parents {
		result = append(result, p)
		result = append(result, children[p.ID]...)
	}
	// Orphaned children (parent already killed) go at the end
	parentIDs := make(map[string]bool, len(parents))
	for _, p := range parents {
		parentIDs[p.ID] = true
	}
	for pid, cs := range children {
		if !parentIDs[pid] {
			result = append(result, cs...)
		}
	}
	return result
}

func timeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}
