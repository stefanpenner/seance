package seance

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/gorilla/websocket"

	"seance/internal/editor"
	"seance/internal/session"
	"seance/internal/tui"
)

//go:embed frontend
var frontendFS embed.FS

const detachedEnvKey = "_SEANCE_DETACHED"

// Auth session store (cookie tokens)
type sessions struct {
	mu sync.RWMutex
	m  map[string]time.Time
}

func newSessions() *sessions {
	return &sessions{m: make(map[string]time.Time)}
}

func (s *sessions) create() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	token := hex.EncodeToString(b)
	s.mu.Lock()
	s.m[token] = time.Now()
	s.mu.Unlock()
	return token
}

func (s *sessions) valid(token string) bool {
	s.mu.RLock()
	_, ok := s.m[token]
	s.mu.RUnlock()
	return ok
}

func (s *sessions) delete(token string) {
	s.mu.Lock()
	delete(s.m, token)
	s.mu.Unlock()
}

// Config
type config struct {
	password   string
	addr       string
	certFile   string
	keyFile    string
	shell      string
	noPassword bool
	noEditor   bool
	editorDir  string
}

func hasFlag(name string) bool {
	for _, arg := range os.Args[1:] {
		if arg == name {
			return true
		}
	}
	return false
}

func loadConfig() config {
	c := config{
		password:   os.Getenv("SEANCE_PASSWORD"),
		addr:       os.Getenv("SEANCE_ADDR"),
		certFile:   os.Getenv("SEANCE_TLS_CERT"),
		keyFile:    os.Getenv("SEANCE_TLS_KEY"),
		shell:      os.Getenv("SEANCE_SHELL"),
		noPassword: hasFlag("--no-password"),
		noEditor:   hasFlag("--no-editor"),
		editorDir:  os.Getenv("SEANCE_EDITOR_DIR"),
	}
	if c.password == "" && !c.noPassword {
		fmt.Fprintln(os.Stderr, "SEANCE_PASSWORD is required (or use --no-password)")
		os.Exit(1)
	}
	if c.addr == "" {
		c.addr = ":8443"
	}
	if c.shell == "" {
		c.shell = os.Getenv("SHELL")
	}
	if c.shell == "" {
		c.shell = "/bin/sh"
	}
	return c
}

// WebSocket upgrader
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// Isolation headers required for SharedArrayBuffer (WASM)
var isolationHeaders = map[string]string{
	"Cross-Origin-Opener-Policy":   "same-origin",
	"Cross-Origin-Embedder-Policy": "require-corp",
}

func setIsolationHeaders(w http.ResponseWriter) {
	for k, v := range isolationHeaders {
		w.Header().Set(k, v)
	}
}

func getSessionToken(r *http.Request) string {
	c, err := r.Cookie("seance_session")
	if err != nil {
		return ""
	}
	return c.Value
}

type serverInstance struct {
	server      *http.Server
	listener    net.Listener
	mgr         *session.Manager
	sess        *sessions
	addr        net.Addr
	editorProxy *editor.EditorProxy
}

func startServer(cfg config) (*serverInstance, error) {
	sess := newSessions()
	mgr := session.NewManager()

	frontendContent, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		return nil, fmt.Errorf("frontend: %w", err)
	}

	var editorProxy *editor.EditorProxy
	if !cfg.noEditor && editor.Available() {
		editorProxy = editor.NewEditorProxy()
	}

	mux := setupMux(cfg, sess, mgr, frontendContent, editorProxy)

	tlsCfg, err := getTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}

	listener, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	tlsListener := tls.NewListener(listener, tlsCfg)

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := server.Serve(tlsListener); err != http.ErrServerClosed {
			log.Printf("server error: %v", err)
		}
	}()

	return &serverInstance{
		server:      server,
		listener:    listener,
		mgr:         mgr,
		sess:        sess,
		addr:        listener.Addr(),
		editorProxy: editorProxy,
	}, nil
}

func logStartupInfo(cfg config, addr net.Addr) {
	log.Printf("listening on https://%s", addr)
	if cfg.certFile == "" {
		log.Println("using auto-generated self-signed certificate")
	}
	if cfg.noPassword {
		log.Println("authentication disabled (--no-password)")
	}
}

func Run() {
	cfg := loadConfig()

	// Set up log writer that feeds into the TUI
	logWriter := tui.NewLogWriter()
	log.SetOutput(logWriter)
	log.SetFlags(log.Ltime)

	si, err := startServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}

	logStartupInfo(cfg, si.addr)

	// Start code-server if available
	var ed *editor.Editor
	if si.editorProxy != nil {
		ed, err = startEditor(cfg, si.editorProxy, logWriter)
		if err != nil {
			log.Printf("editor: %v (continuing without editor)", err)
		}
	}

	// Run TUI on main thread
	model := tui.NewModel(si.mgr, cfg.shell, buildChildEnv())
	model.SetServerURL(fmt.Sprintf("https://%s", si.addr))
	p := tea.NewProgram(model, tea.WithAltScreen())
	logWriter.SetProgram(p)

	// Handle SIGINT/SIGTERM — quit TUI gracefully
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		p.Send(tea.Quit())
	}()

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "tui error: %v\n", err)
	}

	// TUI exited — shut down editor, server, and kill all sessions
	log.SetOutput(os.Stderr) // restore for shutdown logs
	if ed != nil {
		ed.Stop()
	}
	si.mgr.KillAll()
	si.server.Close()
}

func seanceDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".seance")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("cannot create %s: %w", dir, err)
	}
	return dir, nil
}

func RunDaemon() {
	if os.Getenv(detachedEnvKey) == "1" {
		runDaemonChild()
		return
	}
	runDaemonParent()
}

func runDaemonParent() {
	// Validate config before forking so errors show up in the user's terminal
	_ = loadConfig()

	dir, err := seanceDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}

	logPath := filepath.Join(dir, "seance.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: cannot open log file: %v\n", err)
		os.Exit(1)
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: cannot determine executable path: %v\n", err)
		os.Exit(1)
	}

	cmd := &exec.Cmd{
		Path:   exe,
		Args:   os.Args,
		Env:    append(os.Environ(), detachedEnvKey+"=1"),
		Stdout: logFile,
		Stderr: logFile,
		SysProcAttr: &syscall.SysProcAttr{
			Setsid: true,
		},
	}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: cannot start daemon: %v\n", err)
		os.Exit(1)
	}

	pidPath := filepath.Join(dir, "seance.pid")
	os.WriteFile(pidPath, []byte(strconv.Itoa(cmd.Process.Pid)), 0600)

	addr := os.Getenv("SEANCE_ADDR")
	if addr == "" {
		addr = ":8443"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "localhost" + addr
	}

	fmt.Printf("seance daemon started (pid %d)\n", cmd.Process.Pid)
	fmt.Printf("  log: %s\n", logPath)
	fmt.Printf("  pid: %s\n", pidPath)
	fmt.Printf("  url: https://%s\n", addr)
}

func runDaemonChild() {
	dir, err := seanceDir()
	if err != nil {
		log.Fatalf("fatal: %v", err)
	}

	pidPath := filepath.Join(dir, "seance.pid")
	os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0600)

	cfg := loadConfig()

	log.SetOutput(os.Stderr)
	log.SetFlags(log.Ltime)

	si, err := startServer(cfg)
	if err != nil {
		log.Fatalf("fatal: %v", err)
	}

	logStartupInfo(cfg, si.addr)

	// Start code-server if available
	var ed *editor.Editor
	if si.editorProxy != nil {
		ed, err = startEditor(cfg, si.editorProxy, os.Stderr)
		if err != nil {
			log.Printf("editor: %v (continuing without editor)", err)
		}
	}

	log.Println("daemon mode (detached)")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	log.Printf("received %v, shutting down...", sig)
	if ed != nil {
		ed.Stop()
	}
	si.mgr.KillAll()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	si.server.Shutdown(ctx)

	os.Remove(pidPath)
	log.Println("goodbye")
}

func setupMux(cfg config, sess *sessions, mgr *session.Manager, frontendContent fs.FS, editorProxy *editor.EditorProxy) *http.ServeMux {
	mux := http.NewServeMux()

	// Login page
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if cfg.noPassword {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if r.FormValue("password") != cfg.password {
				http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
				return
			}
			token := sess.create()
			http.SetCookie(w, &http.Cookie{
				Name:     "seance_session",
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				Secure:   true,
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		loginHTML, err := fs.ReadFile(frontendContent, "login.html")
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(loginHTML)
	})

	// Logout
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		token := getSessionToken(r)
		if token != "" {
			sess.delete(token)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "seance_session",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   true,
			MaxAge:   -1,
		})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	requireAuth := func(w http.ResponseWriter, r *http.Request) bool {
		if cfg.noPassword {
			return true
		}
		token := getSessionToken(r)
		if !sess.valid(token) {
			if r.Header.Get("Accept") == "application/json" || strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return false
		}
		return true
	}

	// --- Session API ---

	mux.HandleFunc("/api/sessions", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")

		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(mgr.List())

		case http.MethodPost:
			var body struct {
				Name           string `json:"name"`
				Shell          string `json:"shell"`
				ParentID       string `json:"parent_id"`
				SplitFromID    string `json:"split_from_id"`
				SplitDirection string `json:"split_direction"`
			}
			json.NewDecoder(r.Body).Decode(&body)

			shell := body.Shell
			if shell == "" {
				shell = cfg.shell
			}

			// Validate parent exists if specified
			if body.ParentID != "" {
				parent := mgr.Get(body.ParentID)
				if parent == nil {
					w.WriteHeader(http.StatusNotFound)
					json.NewEncoder(w).Encode(map[string]string{"error": "parent session not found"})
					return
				}
				// Inherit shell from parent
				shell = parent.Shell
			}

			ts, err := mgr.Create(body.Name, shell, 80, 24, buildChildEnv(), body.ParentID)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			ts.SplitFromID = body.SplitFromID
			ts.SplitDirection = body.SplitDirection
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(ts.GetInfo())

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/sessions/", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r) {
			return
		}

		rest := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
		if rest == "" {
			http.Error(w, "session id required", http.StatusBadRequest)
			return
		}

		id, suffix, _ := strings.Cut(rest, "/")

		// POST /api/sessions/{id}/close — used by sendBeacon for sub-session cleanup
		if suffix == "close" && r.Method == http.MethodPost {
			if err := mgr.Kill(id); err != nil {
				http.Error(w, "session not found", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// GET /api/sessions/{id}/preview
		if suffix == "preview" && r.Method == http.MethodGet {
			ts := mgr.Get(id)
			if ts == nil {
				http.Error(w, "session not found", http.StatusNotFound)
				return
			}
			snapshot := ts.Ring.Snapshot()
			if len(snapshot) > 4096 {
				snapshot = snapshot[len(snapshot)-4096:]
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write(snapshot)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch r.Method {
		case http.MethodDelete:
			if err := mgr.Kill(id); err != nil {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			w.WriteHeader(http.StatusNoContent)

		case http.MethodPatch:
			var body struct {
				Name string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if err := mgr.Rename(id, body.Name); err != nil {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			ts := mgr.Get(id)
			if ts != nil {
				json.NewEncoder(w).Encode(ts.GetInfo())
			}

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// --- Shutdown API ---

	mux.HandleFunc("/api/shutdown", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		go func() {
			syscall.Kill(os.Getpid(), syscall.SIGTERM)
		}()
	})

	// --- Session-aware PTY WebSocket: /pty/{id} ---

	mux.HandleFunc("/pty/", func(w http.ResponseWriter, r *http.Request) {
		if !cfg.noPassword {
			token := getSessionToken(r)
			if !sess.valid(token) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		id := strings.TrimPrefix(r.URL.Path, "/pty/")
		if id == "" {
			http.Error(w, "session id required", http.StatusBadRequest)
			return
		}

		ts := mgr.Get(id)
		if ts == nil {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}

		if colsStr := r.URL.Query().Get("cols"); colsStr != "" {
			if cols, err := strconv.Atoi(colsStr); err == nil && cols > 0 {
				if rowsStr := r.URL.Query().Get("rows"); rowsStr != "" {
					if rows, err := strconv.Atoi(rowsStr); err == nil && rows > 0 {
						ts.Resize(uint16(cols), uint16(rows), "")
					}
				}
			}
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("websocket upgrade: %v", err)
			return
		}
		defer conn.Close()

		viewer, snapshot := ts.Attach(conn)
		defer ts.Detach(viewer.ID)

		status, _ := json.Marshal(map[string]any{
			"type":         "status",
			"shell":        ts.Shell,
			"session_id":   ts.ID,
			"session_name": ts.Name,
		})
		viewer.SendText(status)

		if len(snapshot) > 0 {
			viewer.SendBinary(snapshot)
		}

		exited, exitCode := ts.Exited()
		if exited {
			exitMsg, _ := json.Marshal(map[string]any{
				"type": "exit",
				"code": exitCode,
			})
			viewer.SendText(exitMsg)
		}

		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				break
			}

			var msg struct {
				Type string `json:"type"`
				Data string `json:"data"`
				Cols int    `json:"cols"`
				Rows int    `json:"rows"`
			}
			if err := json.Unmarshal(message, &msg); err == nil {
				switch msg.Type {
				case "input":
					ts.WriteInput(msg.Data)
					continue
				case "resize":
					if msg.Cols > 0 && msg.Rows > 0 {
						if err := ts.Resize(uint16(msg.Cols), uint16(msg.Rows), viewer.ID); err != nil {
							log.Printf("resize: %v", err)
						}
					}
					continue
				}
			}

			ts.WriteRaw(message)
		}
	})

	// --- Editor (code-server) reverse proxy ---

	if editorProxy != nil {
		mux.Handle("/editor/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !requireAuth(w, r) {
				return
			}
			// No COOP/COEP headers — they break code-server's iframes/workers
			editorProxy.ServeHTTP(w, r)
		}))
	}

	// --- Page routes ---

	mux.HandleFunc("/sessions", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r) {
			return
		}
		setIsolationHeaders(w)
		html, err := fs.ReadFile(frontendContent, "sessions.html")
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(html)
	})

	mux.HandleFunc("/terminal", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r) {
			return
		}
		setIsolationHeaders(w)
		indexHTML, err := fs.ReadFile(frontendContent, "index.html")
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})

	fileServer := http.FileServer(http.FS(frontendContent))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" || r.URL.Path == "/login.html" {
			if cfg.noPassword {
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if !cfg.noPassword {
			token := getSessionToken(r)
			if !sess.valid(token) {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
		}

		if r.URL.Path == "/" {
			http.Redirect(w, r, "/sessions", http.StatusSeeOther)
			return
		}

		setIsolationHeaders(w)
		fileServer.ServeHTTP(w, r)
	})

	return mux
}

// buildChildEnv creates a clean environment for child shell processes.
func buildChildEnv() []string {
	suppress := map[string]bool{
		"TMUX":                true,
		"ZELLIJ":              true,
		"ZELLIJ_SESSION_NAME": true,
		"ZELLIJ_PANE_ID":      true,
		"COLUMNS":             true,
		"LINES":               true,
		"STY":                 true,
		"SSH_CLIENT":          true,
		"SSH_CONNECTION":      true,
		"SSH_TTY":             true,
		"SSH_AUTH_SOCK":       true,
		detachedEnvKey:        true,
	}

	overrides := map[string]string{
		"TERM":                 "xterm-256color",
		"COLORTERM":            "truecolor",
		"TERM_PROGRAM":         "ghostty",
		"TERM_PROGRAM_VERSION": "1.0",
		"LANG":                 "en_US.UTF-8",
		"LC_ALL":               "en_US.UTF-8",
	}

	env := make(map[string]string)
	for _, e := range os.Environ() {
		k, _, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		if suppress[k] || overrides[k] != "" {
			continue
		}
		env[k] = e
	}

	result := make([]string, 0, len(env)+len(overrides))
	for _, v := range env {
		result = append(result, v)
	}
	for k, v := range overrides {
		result = append(result, k+"="+v)
	}
	return result
}

// startEditor creates and starts a code-server instance, wiring it into the proxy.
func startEditor(cfg config, proxy *editor.EditorProxy, logOutput io.Writer) (*editor.Editor, error) {
	baseDir, err := seanceDir()
	if err != nil {
		return nil, err
	}

	ed, err := editor.New(baseDir)
	if err != nil {
		return nil, err
	}

	workDir := cfg.editorDir
	if workDir == "" {
		workDir, _ = os.UserHomeDir()
	}

	ctx := context.Background()
	if err := ed.Start(ctx, workDir, logOutput); err != nil {
		return nil, err
	}

	proxy.SetHandler(ed.Handler())
	log.Println("code-server started at /editor/")

	return ed, nil
}

// TLS
func getTLSConfig(cfg config) (*tls.Config, error) {
	if cfg.certFile != "" && cfg.keyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.certFile, cfg.keyFile)
		if err != nil {
			return nil, fmt.Errorf("loading TLS cert: %w", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}, nil
	}

	cert, err := generateSelfSigned()
	if err != nil {
		return nil, fmt.Errorf("generating self-signed cert: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func generateSelfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "seance"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	fingerprint := sha256.Sum256(certDER)
	log.Printf("certificate fingerprint (SHA-256): %s", hex.EncodeToString(fingerprint[:]))

	return tls.X509KeyPair(certPEM, keyPEM)
}
