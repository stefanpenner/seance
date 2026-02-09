package seance

import (
	"crypto/tls"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"seance/internal/session"
)

const testPassword = "test-secret-123"

// testSetup creates a mux with a valid auth cookie for testing.
func testSetup(t *testing.T) (mux *http.ServeMux, authCookie *http.Cookie) {
	t.Helper()

	cfg := config{
		password: testPassword,
		addr:     ":0",
		shell:    "/bin/sh",
	}
	sess := newSessions()
	mgr := session.NewManager()

	frontendContent, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		t.Fatal(err)
	}

	mux = setupMux(cfg, sess, mgr, frontendContent, nil)

	// Log in to get a valid auth cookie
	form := url.Values{"password": {testPassword}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	resp := rec.Result()
	for _, c := range resp.Cookies() {
		if c.Name == "seance_session" && c.Value != "" {
			authCookie = c
			break
		}
	}
	if authCookie == nil {
		t.Fatal("login did not return a session cookie")
	}

	return mux, authCookie
}

func addCookie(req *http.Request, c *http.Cookie) {
	req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
}

func TestUnauthEndpoints(t *testing.T) {
	mux, _ := testSetup(t)

	tests := []struct {
		name       string
		method     string
		path       string
		wantCode   int // 401 for API, 303 for HTML
		wantHeader string
	}{
		{"GET /api/sessions", http.MethodGet, "/api/sessions", 401, ""},
		{"POST /api/sessions", http.MethodPost, "/api/sessions", 401, ""},
		{"DELETE /api/sessions/x", http.MethodDelete, "/api/sessions/x", 401, ""},
		{"PATCH /api/sessions/x", http.MethodPatch, "/api/sessions/x", 401, ""},
		{"GET /api/sessions/x/preview", http.MethodGet, "/api/sessions/x/preview", 401, ""},
		{"GET /pty/x", http.MethodGet, "/pty/x", 401, ""},
		{"GET /sessions", http.MethodGet, "/sessions", 303, "/login"},
		{"GET /terminal", http.MethodGet, "/terminal", 303, "/login"},
		{"GET /style.css", http.MethodGet, "/style.css", 303, "/login"},
		{"GET /", http.MethodGet, "/", 303, "/login"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantCode)
			}
			if tt.wantHeader != "" {
				loc := rec.Header().Get("Location")
				if loc != tt.wantHeader {
					t.Errorf("got Location %q, want %q", loc, tt.wantHeader)
				}
			}
		})
	}
}

func TestAuthEndpoints(t *testing.T) {
	mux, cookie := testSetup(t)

	tests := []struct {
		name     string
		method   string
		path     string
		wantCode int
	}{
		{"GET /api/sessions", http.MethodGet, "/api/sessions", 200},
		{"GET /sessions", http.MethodGet, "/sessions", 200},
		{"GET /terminal", http.MethodGet, "/terminal", 200},
		// / redirects to /sessions when authenticated
		{"GET /", http.MethodGet, "/", 303},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			addCookie(req, cookie)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantCode)
			}
			// Authenticated requests should never redirect to /login
			if loc := rec.Header().Get("Location"); loc == "/login" {
				t.Errorf("authenticated request redirected to /login")
			}
		})
	}
}

func TestLoginWithoutAuth(t *testing.T) {
	mux, _ := testSetup(t)

	// GET /login should return 200
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("GET /login: got status %d, want 200", rec.Code)
	}

	// POST /login with correct password should set cookie and redirect
	form := url.Values{"password": {testPassword}}
	req = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 303 {
		t.Errorf("POST /login: got status %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("POST /login: got Location %q, want /", loc)
	}

	var found bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "seance_session" && c.Value != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("POST /login: no session cookie set")
	}
}

func TestLogoutWithoutAuth(t *testing.T) {
	mux, _ := testSetup(t)

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 303 {
		t.Errorf("GET /logout: got status %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("GET /logout: got Location %q, want /login", loc)
	}
}

func TestTLSMinVersion(t *testing.T) {
	cfg := config{password: "x"}
	tlsCfg, err := getTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if tlsCfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("TLS MinVersion = %d, want >= %d (TLS 1.2)", tlsCfg.MinVersion, tls.VersionTLS12)
	}
	if len(tlsCfg.Certificates) == 0 {
		t.Error("TLS config has no certificates")
	}
}

func TestCookieFlags(t *testing.T) {
	mux, _ := testSetup(t)

	form := url.Values{"password": {testPassword}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "seance_session" {
			cookie = c
			break
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie returned")
	}

	if !cookie.HttpOnly {
		t.Error("cookie missing HttpOnly flag")
	}
	if !cookie.Secure {
		t.Error("cookie missing Secure flag")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie SameSite = %v, want Strict", cookie.SameSite)
	}
}

func TestInvalidatedSession(t *testing.T) {
	cfg := config{
		password: testPassword,
		addr:     ":0",
		shell:    "/bin/sh",
	}
	sess := newSessions()
	mgr := session.NewManager()

	frontendContent, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		t.Fatal(err)
	}

	mux := setupMux(cfg, sess, mgr, frontendContent, nil)

	// Login
	form := url.Values{"password": {testPassword}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "seance_session" && c.Value != "" {
			cookie = c
			break
		}
	}
	if cookie == nil {
		t.Fatal("login did not return a session cookie")
	}

	// Verify cookie works
	req = httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	addCookie(req, cookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("authenticated request failed with status %d", rec.Code)
	}

	// Invalidate the token server-side
	sess.delete(cookie.Value)

	// Verify subsequent request is rejected
	req = httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	addCookie(req, cookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Errorf("after invalidation: got status %d, want 401", rec.Code)
	}
}

func TestSubSessionCreation(t *testing.T) {
	mux, cookie := testSetup(t)

	// Create parent session
	req := httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(`{"name":"parent"}`))
	req.Header.Set("Content-Type", "application/json")
	addCookie(req, cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 201 {
		t.Fatalf("create parent: got status %d, want 201", rec.Code)
	}

	var parent struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Shell string `json:"shell"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&parent); err != nil {
		t.Fatal(err)
	}
	if parent.ID == "" {
		t.Fatal("parent session has no ID")
	}

	// Create sub-session with parent_id
	body := `{"parent_id":"` + parent.ID + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	addCookie(req, cookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 201 {
		t.Fatalf("create sub-session: got status %d, want 201", rec.Code)
	}

	var child struct {
		ID       string `json:"id"`
		ParentID string `json:"parent_id"`
		Shell    string `json:"shell"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&child); err != nil {
		t.Fatal(err)
	}
	if child.ParentID != parent.ID {
		t.Errorf("child parent_id = %q, want %q", child.ParentID, parent.ID)
	}
	if child.Shell != parent.Shell {
		t.Errorf("child shell = %q, want %q (inherited from parent)", child.Shell, parent.Shell)
	}

	// Create sub-session with invalid parent — should 404
	req = httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(`{"parent_id":"nonexistent"}`))
	req.Header.Set("Content-Type", "application/json")
	addCookie(req, cookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 404 {
		t.Errorf("create with bad parent: got status %d, want 404", rec.Code)
	}
}

func TestCascadingKill(t *testing.T) {
	mux, cookie := testSetup(t)

	// Create parent
	req := httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(`{"name":"parent"}`))
	req.Header.Set("Content-Type", "application/json")
	addCookie(req, cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var parent struct{ ID string `json:"id"` }
	json.NewDecoder(rec.Body).Decode(&parent)

	// Create two children
	for i := 0; i < 2; i++ {
		body := `{"parent_id":"` + parent.ID + `"}`
		req = httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		addCookie(req, cookie)
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 201 {
			t.Fatalf("create child %d: got status %d, want 201", i, rec.Code)
		}
	}

	// Verify 3 sessions exist
	req = httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	addCookie(req, cookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var sessions []struct{ ID string `json:"id"` }
	json.NewDecoder(rec.Body).Decode(&sessions)
	if len(sessions) != 3 {
		t.Fatalf("expected 3 sessions, got %d", len(sessions))
	}

	// Kill parent — should cascade-kill children
	req = httptest.NewRequest(http.MethodDelete, "/api/sessions/"+parent.ID, nil)
	addCookie(req, cookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 204 {
		t.Fatalf("kill parent: got status %d, want 204", rec.Code)
	}

	// Verify all sessions are gone
	req = httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	addCookie(req, cookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	json.NewDecoder(rec.Body).Decode(&sessions)
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions after cascading kill, got %d", len(sessions))
	}
}

func TestCloseEndpoint(t *testing.T) {
	mux, cookie := testSetup(t)

	// Create a session
	req := httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	addCookie(req, cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var sess struct{ ID string `json:"id"` }
	json.NewDecoder(rec.Body).Decode(&sess)

	// POST /api/sessions/{id}/close should kill it
	req = httptest.NewRequest(http.MethodPost, "/api/sessions/"+sess.ID+"/close", nil)
	addCookie(req, cookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 204 {
		t.Errorf("close: got status %d, want 204", rec.Code)
	}

	// Verify session is gone
	req = httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	addCookie(req, cookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var sessions []struct{ ID string `json:"id"` }
	json.NewDecoder(rec.Body).Decode(&sessions)
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions after close, got %d", len(sessions))
	}

	// POST close on nonexistent should 404
	req = httptest.NewRequest(http.MethodPost, "/api/sessions/nonexistent/close", nil)
	addCookie(req, cookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 404 {
		t.Errorf("close nonexistent: got status %d, want 404", rec.Code)
	}
}

func TestWrongPassword(t *testing.T) {
	mux, _ := testSetup(t)

	form := url.Values{"password": {"wrong-password"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 303 {
		t.Errorf("got status %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login?error=1" {
		t.Errorf("got Location %q, want /login?error=1", loc)
	}

	// Should not set a session cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "seance_session" && c.Value != "" {
			t.Error("wrong password should not set a session cookie")
		}
	}
}
