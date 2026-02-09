package seance

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"slices"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/term"

	"seance/internal/session"
)

type cliConfig struct {
	addr     string
	password string
	insecure bool
}

func loadCLIConfig() cliConfig {
	cc := cliConfig{
		addr:     os.Getenv("SEANCE_ADDR"),
		password: os.Getenv("SEANCE_PASSWORD"),
		insecure: hasFlag("--insecure") || hasFlag("-k"),
	}
	if cc.addr == "" {
		cc.addr = ":8443"
	}
	if strings.HasPrefix(cc.addr, ":") {
		cc.addr = "localhost" + cc.addr
	}
	// Default to insecure when connecting to localhost with self-signed certs
	host := cc.addr
	if idx := strings.LastIndex(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	if !cc.insecure && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
		cc.insecure = true
	}
	return cc
}

func newCLIClient(cc cliConfig) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cc.insecure,
			},
		},
		Timeout: 10 * time.Second,
	}
}

func authenticate(client *http.Client, baseURL, password string) error {
	if hasFlag("--no-password") || password == "" {
		return nil
	}
	resp, err := client.PostForm(baseURL+"/login", url.Values{
		"password": {password},
	})
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	resp.Body.Close()
	return nil
}

func timeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// RunList fetches and displays all sessions from a running seance server.
func RunList() {
	cc := loadCLIConfig()
	baseURL := "https://" + cc.addr
	client := newCLIClient(cc)

	if err := authenticate(client, baseURL, cc.password); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	resp, err := client.Get(baseURL + "/api/sessions")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		fmt.Fprintln(os.Stderr, "error: unauthorized (check SEANCE_PASSWORD)")
		os.Exit(1)
	}

	var sessions []session.Info
	if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if len(sessions) == 0 {
		fmt.Println("no sessions")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tSHELL\tSIZE\tVIEWERS\tSTATUS\tCREATED")
	for _, s := range sessions {
		status := "running"
		if s.Exited {
			status = fmt.Sprintf("exited(%d)", s.ExitCode)
		}
		size := fmt.Sprintf("%dx%d", s.Cols, s.Rows)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			s.ID, s.Name, s.Shell, size, s.Viewers, status, timeAgo(s.CreatedAt))
	}
	w.Flush()
}

// RunAttach connects to a session's PTY via WebSocket and bridges stdin/stdout.
func RunAttach(sessionID string) {
	if sessionID == "" {
		RunList()
		fmt.Fprintln(os.Stderr, "\nUsage: seance attach <session-id>")
		os.Exit(0)
	}

	cc := loadCLIConfig()
	baseURL := "https://" + cc.addr
	client := newCLIClient(cc)

	if err := authenticate(client, baseURL, cc.password); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fd := int(os.Stdin.Fd())
	cols, rows, err := term.GetSize(fd)
	if err != nil {
		cols = 80
		rows = 24
	}

	wsURL := fmt.Sprintf("wss://%s/pty/%s?cols=%d&rows=%d", cc.addr, sessionID, cols, rows)

	dialer := websocket.Dialer{
		TLSClientConfig: client.Transport.(*http.Transport).TLSClientConfig,
	}

	// Extract cookies from the jar for the WebSocket handshake.
	u, _ := url.Parse(baseURL)
	cookies := client.Jar.Cookies(u)
	header := http.Header{}
	for _, c := range cookies {
		header.Add("Cookie", c.String())
	}

	conn, resp, err := dialer.Dial(wsURL, header)
	if err != nil {
		if resp != nil {
			switch resp.StatusCode {
			case http.StatusUnauthorized:
				fmt.Fprintln(os.Stderr, "error: unauthorized (check SEANCE_PASSWORD)")
				os.Exit(1)
			case http.StatusNotFound:
				fmt.Fprintln(os.Stderr, "error: session not found")
				os.Exit(1)
			}
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to set raw terminal: %v\n", err)
		os.Exit(1)
	}
	defer term.Restore(fd, oldState)

	done := make(chan struct{})
	var wsMu sync.Mutex

	// Goroutine 1 — WS → stdout
	go func() {
		defer close(done)
		for {
			msgType, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			switch msgType {
			case websocket.BinaryMessage:
				os.Stdout.Write(data)
			case websocket.TextMessage:
				var msg struct {
					Type string `json:"type"`
					Code int    `json:"code"`
				}
				if json.Unmarshal(data, &msg) == nil && msg.Type == "exit" {
					fmt.Fprintf(os.Stderr, "\r\n[session exited with code %d]\r\n", msg.Code)
					return
				}
			}
		}
	}()

	// Goroutine 2 — SIGWINCH
	winchCh := make(chan os.Signal, 1)
	signal.Notify(winchCh, syscall.SIGWINCH)
	go func() {
		for {
			select {
			case <-winchCh:
				c, r, err := term.GetSize(fd)
				if err == nil && c > 0 && r > 0 {
					msg, _ := json.Marshal(map[string]any{"type": "resize", "cols": c, "rows": r})
					wsMu.Lock()
					conn.WriteMessage(websocket.TextMessage, msg)
					wsMu.Unlock()
				}
			case <-done:
				return
			}
		}
	}()

	// Goroutine 3 — stdin → WS
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				conn.Close()
				return
			}
			data := buf[:n]
			// Check for detach key: Ctrl+\ (0x1c)
			if slices.Contains(data, 0x1c) {
				fmt.Fprintf(os.Stderr, "\r\n[detached]\r\n")
				conn.Close()
				return
			}
			msg, _ := json.Marshal(map[string]string{"type": "input", "data": string(data)})
			wsMu.Lock()
			conn.WriteMessage(websocket.TextMessage, msg)
			wsMu.Unlock()
		}
	}()

	<-done
}

// RunKill terminates a session on a running seance server.
func RunKill(sessionID string) {
	if sessionID == "" {
		RunList()
		fmt.Fprintln(os.Stderr, "\nUsage: seance kill <session-id>")
		os.Exit(0)
	}

	cc := loadCLIConfig()
	baseURL := "https://" + cc.addr
	client := newCLIClient(cc)

	if err := authenticate(client, baseURL, cc.password); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	req, err := http.NewRequest(http.MethodDelete, baseURL+"/api/sessions/"+sessionID, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		fmt.Printf("killed session %s\n", sessionID)
	case http.StatusUnauthorized:
		fmt.Fprintln(os.Stderr, "error: unauthorized (check SEANCE_PASSWORD)")
		os.Exit(1)
	case http.StatusNotFound:
		fmt.Fprintf(os.Stderr, "error: session %s not found\n", sessionID)
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "error: unexpected status %d\n", resp.StatusCode)
		os.Exit(1)
	}
}
