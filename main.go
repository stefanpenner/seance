package main

import (
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
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

//go:embed frontend
var frontendFS embed.FS

// Session store
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
	password string
	addr     string
	certFile string
	keyFile  string
	shell    string
}

func loadConfig() config {
	c := config{
		password: os.Getenv("SEANCE_PASSWORD"),
		addr:     os.Getenv("SEANCE_ADDR"),
		certFile: os.Getenv("SEANCE_TLS_CERT"),
		keyFile:  os.Getenv("SEANCE_TLS_KEY"),
		shell:    os.Getenv("SEANCE_SHELL"),
	}
	if c.password == "" {
		fmt.Fprintln(os.Stderr, "SEANCE_PASSWORD is required")
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

func main() {
	cfg := loadConfig()
	sess := newSessions()

	frontendContent, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	// Login page
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
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
		// GET
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

	// PTY WebSocket
	mux.HandleFunc("/pty", func(w http.ResponseWriter, r *http.Request) {
		token := getSessionToken(r)
		if !sess.valid(token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		handlePTY(w, r, cfg)
	})

	// Static files (auth-protected)
	fileServer := http.FileServer(http.FS(frontendContent))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Allow login page assets without auth
		if r.URL.Path == "/login" || r.URL.Path == "/login.html" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		token := getSessionToken(r)
		if !sess.valid(token) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		setIsolationHeaders(w)

		// Serve index.html for root
		if r.URL.Path == "/" {
			indexHTML, err := fs.ReadFile(frontendContent, "index.html")
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(indexHTML)
			return
		}

		fileServer.ServeHTTP(w, r)
	})

	// TLS config
	tlsCfg, err := getTLSConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}

	listener, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		log.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, tlsCfg)

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down...")
		server.Close()
	}()

	log.Printf("seance listening on https://%s", listener.Addr())
	if cfg.certFile == "" {
		log.Println("using auto-generated self-signed certificate")
	}
	if err := server.Serve(tlsListener); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

// PTY handling
func handlePTY(w http.ResponseWriter, r *http.Request, cfg config) {
	cols, _ := strconv.Atoi(r.URL.Query().Get("cols"))
	rows, _ := strconv.Atoi(r.URL.Query().Get("rows"))
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}

	shell := r.URL.Query().Get("shell")
	if shell == "" {
		shell = cfg.shell
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("websocket upgrade: %v", err)
		return
	}
	defer conn.Close()

	// Parse shell command
	parts := strings.Fields(shell)
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"TERM_PROGRAM=ghostty",
		"TERM_PROGRAM_VERSION=1.0",
	)

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Cols: uint16(cols),
		Rows: uint16(rows),
	})
	if err != nil {
		msg, _ := json.Marshal(map[string]any{
			"type":    "error",
			"message": fmt.Sprintf("failed to spawn shell: %v", err),
		})
		conn.WriteMessage(websocket.TextMessage, msg)
		return
	}
	defer ptmx.Close()

	// Send status
	status, _ := json.Marshal(map[string]any{
		"type":  "status",
		"shell": shell,
	})
	conn.WriteMessage(websocket.TextMessage, status)

	// PTY -> WebSocket (BinaryMessage so the client's streaming TextDecoder
	// handles multi-byte UTF-8 split across reads correctly)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 32*1024)
		for {
			n, err := ptmx.Read(buf)
			if err != nil {
				break
			}
			if err := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				break
			}
		}
		// Send exit message
		exitCode := 0
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}
		exitMsg, _ := json.Marshal(map[string]any{
			"type": "exit",
			"code": exitCode,
		})
		conn.WriteMessage(websocket.TextMessage, exitMsg)
	}()

	// WebSocket -> PTY
	go func() {
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				break
			}

			// Try to parse as JSON command
			var msg struct {
				Type string `json:"type"`
				Data string `json:"data"`
				Cols int    `json:"cols"`
				Rows int    `json:"rows"`
			}
			if err := json.Unmarshal(message, &msg); err == nil {
				switch msg.Type {
				case "input":
					ptmx.WriteString(msg.Data)
					continue
				case "resize":
					if msg.Cols > 0 && msg.Rows > 0 {
						pty.Setsize(ptmx, &pty.Winsize{
							Cols: uint16(msg.Cols),
							Rows: uint16(msg.Rows),
						})
					}
					continue
				}
			}

			// Raw text fallback
			ptmx.Write(message)
		}
		// When WS closes, kill the process
		cmd.Process.Signal(syscall.SIGHUP)
	}()

	<-done
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

	// Generate self-signed cert
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

	// Print fingerprint so user can verify
	fingerprint := sha256.Sum256(certDER)
	log.Printf("certificate fingerprint (SHA-256): %s", hex.EncodeToString(fingerprint[:]))

	return tls.X509KeyPair(certPEM, keyPEM)
}
