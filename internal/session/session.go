package session

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

// RingBuffer is a circular byte buffer with a fixed capacity.
type RingBuffer struct {
	mu   sync.Mutex
	buf  []byte
	cap  int
	pos  int // next write position
	full bool
}

func NewRingBuffer(capacity int) *RingBuffer {
	return &RingBuffer{
		buf: make([]byte, capacity),
		cap: capacity,
	}
}

func (r *RingBuffer) Write(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for len(p) > 0 {
		n := copy(r.buf[r.pos:], p)
		r.pos += n
		if r.pos >= r.cap {
			r.pos = 0
			r.full = true
		}
		p = p[n:]
	}
}

// Snapshot returns a copy of all buffered bytes in order (oldest first),
// with stale CPR (cursor position report) responses stripped.
func (r *RingBuffer) Snapshot() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []byte
	if !r.full {
		out = make([]byte, r.pos)
		copy(out, r.buf[:r.pos])
	} else {
		out = make([]byte, r.cap)
		n := copy(out, r.buf[r.pos:])
		copy(out[n:], r.buf[:r.pos])
	}
	return stripCPR(out)
}

// stripCPR removes cursor position report responses (\x1b[{row};{col}R)
// that would display as garbage when replayed to a new viewer.
func stripCPR(data []byte) []byte {
	result := make([]byte, 0, len(data))
	i := 0
	for i < len(data) {
		if i+2 < len(data) && data[i] == 0x1b && data[i+1] == '[' {
			j := i + 2
			for j < len(data) && data[j] >= '0' && data[j] <= '9' {
				j++
			}
			if j < len(data) && data[j] == ';' {
				j++
				for j < len(data) && data[j] >= '0' && data[j] <= '9' {
					j++
				}
			}
			if j < len(data) && data[j] == 'R' {
				i = j + 1
				continue
			}
		}
		result = append(result, data[i])
		i++
	}
	return result
}

// Viewer represents a WebSocket connection attached to a session.
type Viewer struct {
	ID   string
	conn *websocket.Conn
	mu   sync.Mutex
}

func (v *Viewer) SendBinary(data []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (v *Viewer) SendText(data []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.conn.WriteMessage(websocket.TextMessage, data)
}

// Info is the JSON-serializable session metadata.
type Info struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Shell          string    `json:"shell"`
	ParentID       string    `json:"parent_id,omitempty"`
	SplitFromID    string    `json:"split_from_id,omitempty"`
	SplitDirection string    `json:"split_direction,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	Cols           int       `json:"cols"`
	Rows           int       `json:"rows"`
	Viewers        int       `json:"viewers"`
	Exited         bool      `json:"exited"`
	ExitCode       int       `json:"exit_code,omitempty"`
}

// Terminal is a persistent PTY session that survives WebSocket disconnects.
type Terminal struct {
	ID             string
	Name           string
	Shell          string
	ParentID       string
	SplitFromID    string
	SplitDirection string
	CreatedAt      time.Time

	ptmx *os.File
	cmd  *exec.Cmd
	cols uint16
	rows uint16

	Mu       sync.RWMutex
	exited   bool
	exitCode int
	Ring     *RingBuffer
	viewers  map[string]*Viewer
}

func newTerminal(id, name, shell string, cols, rows uint16, env []string, bufSize int, cwd string) (*Terminal, error) {
	parts := strings.Fields(shell)
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Env = env
	if cwd != "" {
		cmd.Dir = cwd
	}

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Cols: cols,
		Rows: rows,
	})
	if err != nil {
		return nil, fmt.Errorf("spawn shell: %w", err)
	}

	s := &Terminal{
		ID:        id,
		Name:      name,
		Shell:     shell,
		CreatedAt: time.Now(),
		ptmx:      ptmx,
		cmd:       cmd,
		cols:      cols,
		rows:      rows,
		Ring:      NewRingBuffer(bufSize),
		viewers:   make(map[string]*Viewer),
	}

	go s.readLoop()

	return s, nil
}

func (s *Terminal) readLoop() {
	buf := make([]byte, 32*1024)
	for {
		n, err := s.ptmx.Read(buf)
		if err != nil {
			break
		}
		data := buf[:n]

		s.Ring.Write(data)

		s.Mu.RLock()
		for _, v := range s.viewers {
			_ = v.SendBinary(data)
		}
		s.Mu.RUnlock()
	}

	exitCode := 0
	if err := s.cmd.Wait(); err != nil {
		if es, ok := err.(*exec.ExitError); ok {
			exitCode = es.ExitCode()
		}
	}
	if s.cmd.ProcessState != nil {
		exitCode = s.cmd.ProcessState.ExitCode()
	}

	s.Mu.Lock()
	s.exited = true
	s.exitCode = exitCode
	s.Mu.Unlock()

	exitMsg, _ := json.Marshal(map[string]any{
		"type": "exit",
		"code": exitCode,
	})
	s.Mu.RLock()
	for _, v := range s.viewers {
		_ = v.SendText(exitMsg)
	}
	s.Mu.RUnlock()
}

// Attach adds a WebSocket connection as a viewer. Returns the ring snapshot for catch-up.
func (s *Terminal) Attach(conn *websocket.Conn) (*Viewer, []byte) {
	b := make([]byte, 16)
	rand.Read(b)
	vid := hex.EncodeToString(b)

	v := &Viewer{ID: vid, conn: conn}
	snapshot := s.Ring.Snapshot()

	s.Mu.Lock()
	s.viewers[vid] = v
	s.Mu.Unlock()

	return v, snapshot
}

// Detach removes a viewer. The session keeps running.
func (s *Terminal) Detach(viewerID string) {
	s.Mu.Lock()
	delete(s.viewers, viewerID)
	s.Mu.Unlock()
}

func (s *Terminal) WriteInput(data string) { s.ptmx.WriteString(data) }
func (s *Terminal) WriteRaw(data []byte)   { s.ptmx.Write(data) }

// Exited returns the exited state and exit code.
func (s *Terminal) Exited() (bool, int) {
	s.Mu.RLock()
	defer s.Mu.RUnlock()
	return s.exited, s.exitCode
}

// Resize changes the PTY dimensions and notifies other viewers.
func (s *Terminal) Resize(cols, rows uint16, excludeViewerID string) error {
	if err := pty.Setsize(s.ptmx, &pty.Winsize{Cols: cols, Rows: rows}); err != nil {
		return fmt.Errorf("pty resize: %w", err)
	}

	s.Mu.Lock()
	s.cols = cols
	s.rows = rows
	s.Mu.Unlock()

	msg, _ := json.Marshal(map[string]any{
		"type": "resize_notify",
		"cols": cols,
		"rows": rows,
	})
	s.Mu.RLock()
	for _, v := range s.viewers {
		if v.ID != excludeViewerID {
			_ = v.SendText(msg)
		}
	}
	s.Mu.RUnlock()

	return nil
}

// GetInfo returns the JSON-serializable session info.
func (s *Terminal) GetInfo() Info {
	s.Mu.RLock()
	defer s.Mu.RUnlock()
	return Info{
		ID:             s.ID,
		Name:           s.Name,
		Shell:          s.Shell,
		ParentID:       s.ParentID,
		SplitFromID:    s.SplitFromID,
		SplitDirection: s.SplitDirection,
		CreatedAt:      s.CreatedAt,
		Cols:           int(s.cols),
		Rows:           int(s.rows),
		Viewers:        len(s.viewers),
		Exited:         s.exited,
		ExitCode:       s.exitCode,
	}
}

// Kill sends SIGHUP, waits briefly, then SIGKILL if needed.
func (s *Terminal) Kill() {
	s.Mu.RLock()
	exited := s.exited
	s.Mu.RUnlock()

	if exited {
		s.ptmx.Close()
		return
	}

	_ = s.cmd.Process.Signal(syscall.SIGHUP)

	done := make(chan struct{})
	go func() {
		s.cmd.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = s.cmd.Process.Signal(syscall.SIGKILL)
		<-done
	}
	s.ptmx.Close()
}

// Manager manages all terminal sessions.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Terminal
	counter  int
	bufSize  int
}

func NewManager() *Manager {
	bufSize := 1024 * 1024
	if env := os.Getenv("SEANCE_BUFFER_SIZE"); env != "" {
		if n, err := strconv.Atoi(env); err == nil && n > 0 {
			bufSize = n
		}
	}
	return &Manager{
		sessions: make(map[string]*Terminal),
		bufSize:  bufSize,
	}
}

func (m *Manager) Create(name, shell string, cols, rows uint16, env []string, parentID string, cwd string) (*Terminal, error) {
	b := make([]byte, 8)
	rand.Read(b)
	id := hex.EncodeToString(b)

	m.mu.Lock()
	m.counter++
	if name == "" {
		name = fmt.Sprintf("session-%d", m.counter)
	}
	m.mu.Unlock()

	s, err := newTerminal(id, name, shell, cols, rows, env, m.bufSize, cwd)
	if err != nil {
		return nil, err
	}
	s.ParentID = parentID

	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()

	if parentID != "" {
		log.Printf("sub-session created: %s (%s) parent=%s", s.Name, s.ID, parentID)
	} else {
		log.Printf("session created: %s (%s)", s.Name, s.ID)
	}
	return s, nil
}

func (m *Manager) Get(id string) *Terminal {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}

func (m *Manager) List() []Info {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]Info, 0, len(m.sessions))
	for _, s := range m.sessions {
		list = append(list, s.GetInfo())
	}
	return list
}

func (m *Manager) Kill(id string) error {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("session not found: %s", id)
	}
	delete(m.sessions, id)

	// Collect children (sessions whose ParentID == id)
	var children []*Terminal
	for cid, cs := range m.sessions {
		if cs.ParentID == id {
			children = append(children, cs)
			delete(m.sessions, cid)
		}
	}
	m.mu.Unlock()

	s.Kill()
	log.Printf("session killed: %s (%s)", s.Name, s.ID)

	for _, child := range children {
		child.Kill()
		log.Printf("sub-session killed: %s (%s) parent=%s", child.Name, child.ID, id)
	}
	return nil
}

func (m *Manager) Rename(id, name string) error {
	m.mu.RLock()
	s, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("session not found: %s", id)
	}
	s.Mu.Lock()
	s.Name = name
	s.Mu.Unlock()
	return nil
}

// KillAll kills all sessions. Used during graceful shutdown.
func (m *Manager) KillAll() {
	m.mu.Lock()
	sessions := make([]*Terminal, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.sessions = make(map[string]*Terminal)
	m.mu.Unlock()

	for _, s := range sessions {
		s.Kill()
	}
}
