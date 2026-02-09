package tui

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"seance/internal/session"
)

// RemoteProvider wraps HTTP client calls to a running seance daemon.
type RemoteProvider struct {
	client  *http.Client
	baseURL string
}

func NewRemoteProvider(client *http.Client, baseURL string) *RemoteProvider {
	return &RemoteProvider{
		client:  client,
		baseURL: baseURL,
	}
}

func (p *RemoteProvider) List() ([]session.Info, error) {
	resp, err := p.client.Get(p.baseURL + "/api/sessions")
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("unauthorized (check SEANCE_PASSWORD)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var sessions []session.Info
	if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
		return nil, fmt.Errorf("decode sessions: %w", err)
	}
	return sessions, nil
}

func (p *RemoteProvider) Create(name, shell string, cols, rows uint16, env []string, parentID string) (session.Info, error) {
	body, _ := json.Marshal(map[string]any{
		"name":      name,
		"shell":     shell,
		"parent_id": parentID,
	})
	resp, err := p.client.Post(p.baseURL+"/api/sessions", "application/json", strings.NewReader(string(body)))
	if err != nil {
		return session.Info{}, fmt.Errorf("create session: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return session.Info{}, fmt.Errorf("create session: status %d", resp.StatusCode)
	}

	var info session.Info
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return session.Info{}, fmt.Errorf("decode session: %w", err)
	}
	return info, nil
}

func (p *RemoteProvider) Kill(id string) error {
	req, err := http.NewRequest(http.MethodDelete, p.baseURL+"/api/sessions/"+id, nil)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("kill session: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("session not found: %s", id)
	}
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("kill session: status %d", resp.StatusCode)
	}
	return nil
}

func (p *RemoteProvider) Rename(id string, name string) error {
	body, _ := json.Marshal(map[string]string{"name": name})
	req, err := http.NewRequest(http.MethodPatch, p.baseURL+"/api/sessions/"+id, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("rename session: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("session not found: %s", id)
	}
	return nil
}

func (p *RemoteProvider) ServerURL() string {
	return p.baseURL
}

// SubscribeLogs connects to the /api/logs SSE endpoint and feeds LogLine
// messages into the TUI program. Blocks until the context is cancelled
// or the connection drops.
func (p *RemoteProvider) SubscribeLogs(ctx context.Context, program *tea.Program) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/api/logs", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("subscribe logs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("subscribe logs: status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			program.Send(LogLine(line[6:]))
		}
	}
	return scanner.Err()
}
