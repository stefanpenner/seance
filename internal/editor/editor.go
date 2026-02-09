package editor

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"time"
)

// Available reports whether a code-server archive is embedded in this build.
func Available() bool {
	return len(codeServerArchive) > 0
}

// Editor manages a code-server subprocess communicating over a Unix socket.
type Editor struct {
	cmd        *exec.Cmd
	cancel     context.CancelFunc
	done       chan struct{}
	socketPath string
	cacheDir   string
	binPath    string
}

// New prepares a code-server instance. It extracts the embedded archive to a
// hash-based cache directory under baseDir (typically ~/.seance/) if not
// already extracted.
func New(baseDir string) (*Editor, error) {
	if len(codeServerArchive) == 0 {
		return nil, fmt.Errorf("no code-server archive embedded for this platform")
	}

	h := sha256.Sum256(codeServerArchive)
	hash := hex.EncodeToString(h[:8]) // 16-char prefix is plenty
	cacheDir := filepath.Join(baseDir, "code-server-"+hash)
	marker := filepath.Join(cacheDir, ".extracted")

	if _, err := os.Stat(marker); err != nil {
		// Need to extract
		if err := os.MkdirAll(cacheDir, 0700); err != nil {
			return nil, fmt.Errorf("create cache dir: %w", err)
		}
		if err := extractTarGz(codeServerArchive, cacheDir); err != nil {
			os.RemoveAll(cacheDir)
			return nil, fmt.Errorf("extract code-server: %w", err)
		}
		if err := os.WriteFile(marker, []byte("ok\n"), 0600); err != nil {
			return nil, fmt.Errorf("write marker: %w", err)
		}
	}

	// Locate the code-server binary. The tarball extracts to
	// code-server-<version>-<platform>/bin/code-server (or lib/node within).
	binPath, err := findBinary(cacheDir)
	if err != nil {
		return nil, err
	}

	socketPath := filepath.Join(baseDir, "code-server.sock")

	return &Editor{
		socketPath: socketPath,
		cacheDir:   cacheDir,
		binPath:    binPath,
	}, nil
}

// Start launches the code-server subprocess. workDir is the directory
// code-server opens by default. logOutput receives stdout/stderr.
func (e *Editor) Start(ctx context.Context, workDir string, logOutput io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.done = make(chan struct{})

	// Remove stale socket
	os.Remove(e.socketPath)

	args := []string{
		"--socket", e.socketPath,
		"--auth", "none",
		"--disable-telemetry",
		"--disable-update-check",
		"--disable-workspace-trust",
		"--base-path", "/editor",
		"--user-data-dir", filepath.Join(e.cacheDir, "data"),
		"--extensions-dir", filepath.Join(e.cacheDir, "extensions"),
	}
	if workDir != "" {
		args = append(args, workDir)
	}

	e.cmd = exec.CommandContext(ctx, e.binPath, args...)
	e.cmd.Stdout = logOutput
	e.cmd.Stderr = logOutput
	e.cmd.Env = append(os.Environ(), "VSCODE_IPC_HOOK_CLI=")

	if err := e.cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("start code-server: %w", err)
	}

	go func() {
		e.cmd.Wait()
		close(e.done)
	}()

	// Poll for the socket to appear (code-server takes a couple seconds)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(e.socketPath); err == nil {
			// Try connecting to verify it's listening
			conn, err := net.DialTimeout("unix", e.socketPath, 500*time.Millisecond)
			if err == nil {
				conn.Close()
				return nil
			}
		}
		select {
		case <-e.done:
			return fmt.Errorf("code-server exited before socket was ready")
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}

	return fmt.Errorf("code-server socket not ready after 15s")
}

// Stop gracefully shuts down code-server.
func (e *Editor) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
	if e.done != nil {
		select {
		case <-e.done:
		case <-time.After(5 * time.Second):
			if e.cmd != nil && e.cmd.Process != nil {
				e.cmd.Process.Kill()
			}
		}
	}
	os.Remove(e.socketPath)
}

// Handler returns an http.Handler that reverse-proxies to code-server's Unix socket.
func (e *Editor) Handler() http.Handler {
	target, _ := url.Parse("http://code-server")
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			// Preserve the original Host header for code-server
			r.Out.Host = r.In.Host
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", e.socketPath, 5*time.Second)
			},
		},
	}
	return proxy
}

// EditorProxy is an http.Handler that initially returns 503 until the real
// handler is swapped in once code-server is ready. This allows registering
// the route at mux setup time before code-server has started.
type EditorProxy struct {
	handler atomic.Value // stores http.Handler
}

func NewEditorProxy() *EditorProxy {
	return &EditorProxy{}
}

func (p *EditorProxy) SetHandler(h http.Handler) {
	p.handler.Store(h)
}

func (p *EditorProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h, ok := p.handler.Load().(http.Handler); ok && h != nil {
		h.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Retry-After", "2")
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write([]byte(`<!doctype html>
<html><head><meta charset="utf-8"><title>seance — editor</title>
<meta http-equiv="refresh" content="2">
<style>body{background:#1a1b26;color:#c0caf5;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.msg{text-align:center}.msg h2{color:#bb9af7;margin-bottom:8px}.spinner{display:inline-block;width:20px;height:20px;border:2px solid #29334d;border-top-color:#7aa2f7;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}</style></head>
<body><div class="msg"><div class="spinner"></div><h2>Editor starting...</h2><p>This page will refresh automatically.</p></div></body></html>`))
}

// extractTarGz decompresses a gzip'd tar archive into dst.
func extractTarGz(data []byte, dst string) error {
	gr, err := gzip.NewReader(bytesReader(data))
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}

		target := filepath.Join(dst, hdr.Name)

		// Basic path traversal protection
		if !filepath.IsLocal(hdr.Name) {
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)|0700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			os.Remove(target) // remove if exists
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		}
	}
	return nil
}

// findBinary locates the code-server executable inside the extracted cache dir.
func findBinary(cacheDir string) (string, error) {
	// The tarball extracts a single directory like code-server-4.x.y-linux-amd64/
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return "", fmt.Errorf("read cache dir: %w", err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		candidate := filepath.Join(cacheDir, e.Name(), "bin", "code-server")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// Maybe extracted flat
	candidate := filepath.Join(cacheDir, "bin", "code-server")
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}

	return "", fmt.Errorf("code-server binary not found in %s", cacheDir)
}

type bytesReaderWrapper struct {
	data []byte
	pos  int
}

func bytesReader(data []byte) io.Reader {
	return &bytesReaderWrapper{data: data}
}

func (r *bytesReaderWrapper) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
