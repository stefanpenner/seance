# Pluggable Tunnels & Auth Hardening

## Goal

Make seance's networking and auth pluggable so users can expose a terminal
via ngrok/cloudflare/frp with a config change, and harden password auth with
session TTL + rate limiting. Zero-config default still works as today.

## Tunnel Interface

```go
type Tunnel interface {
    Listen(ctx context.Context) (net.Listener, publicURL string, err error)
    Close(ctx context.Context) error
    Name() string
}
```

Returns `net.Listener` because that's what `http.Server.Serve` accepts, and
both `net.Listen` and ngrok's SDK produce one.

### Providers

**direct** (default) — current behavior, `net.Listen("tcp", addr)` + TLS.

**ngrok** — `golang.ngrok.com/ngrok` Go SDK. Embeds directly, returns a
listener with a public URL. TLS terminated at ngrok edge, so skip local TLS
wrapping. Supports custom domains, traffic policies (edge auth, IP allowlists).

**cloudflare** (future) — no Go SDK for tunnel creation. Would need to shell
out to `cloudflared` or use their API. Cloudflare Access provides OAuth/SSO at
the edge. Harder to embed as a library.

**frp** (future) — open source, self-hosted. Requires running your own frp
server. No built-in edge auth. More DIY.

## Auth Interface

```go
type Authenticator interface {
    Middleware(next http.Handler) http.Handler
    IsAuthenticated(r *http.Request) bool
    LoginHandler() http.Handler
    LogoutHandler() http.Handler
}
```

`IsAuthenticated` separate from `Middleware` because WebSocket/API endpoints
need 401 responses, not redirects.

### Providers

**password** (default) — current flow, hardened:
- Session TTL (default 24h, background reaper)
- Per-IP rate limiting on login (default 5 attempts / 15min window)
- `subtle.ConstantTimeCompare` for password check
- `X-Forwarded-For` awareness for real client IP behind tunnels

**oauth** (future) — app-level GitHub/Google OAuth2/OIDC.

**ngrok edge auth** (future) — set `auth.method = "none"`, let ngrok's
traffic policy handle OAuth at the edge before traffic reaches seance.

**mtls** (future) — mutual TLS with client certificates.

## Config

TOML config file, optional (`--config seance.toml`). Env vars override for secrets.

```toml
[server]
addr = ":8443"
shell = "/bin/zsh"
tls_cert = ""
tls_key = ""

[auth]
method = "password"

[auth.password]
password = ""             # env: SEANCE_PASSWORD
session_ttl = "24h"
rate_limit_max = 5
rate_limit_window = "15m"

[tunnel]
provider = "direct"

[tunnel.ngrok]
authtoken = ""            # env: NGROK_AUTHTOKEN
domain = ""
```

## Security Tests

Every security property gets a test that fails if someone accidentally breaks it:

- Session TTL actually expires sessions
- Rate limiting blocks after N failures, resets on success, per-IP isolated
- Session tokens have sufficient entropy, no duplicates
- Cookies have HttpOnly, Secure, SameSite=Strict
- All protected routes reject unauthenticated requests
- API/WebSocket routes return 401 (not redirect)
- COOP/COEP headers present on protected pages
- Logout invalidates session server-side (cookie replay fails)
- Env vars override config file values for secrets

## File Layout

```
auth/
  auth.go          — interface
  password.go      — password provider + hardening
  password_test.go — security tests

tunnel/
  tunnel.go        — interface
  direct.go        — current behavior
  ngrok.go         — ngrok SDK

config.go          — TOML + env overrides
config_test.go     — config validation tests
server.go          — route setup, headers
server_test.go     — route protection tests
pty.go             — buildChildEnv()
tls.go             — TLS config, self-signed gen
main.go            — slim wiring (~80 lines)
```

## New Dependencies

- `github.com/BurntSushi/toml` — config parsing
- `golang.ngrok.com/ngrok` — ngrok tunnel SDK

## Key Design Decisions

- **Switch statement over registry**: simple and debuggable at 2-4 providers.
  Introduce registry if/when there are 6+.
- **TLS conditional on tunnel**: ngrok terminates TLS at edge, double-TLS
  breaks connections. Direct mode wraps with TLS, tunnel modes don't.
- **Per-IP rate limiting**: protects against brute-force on unauthenticated
  login endpoint. Behind ngrok, uses X-Forwarded-For for real client IP.
- **Env vars override config**: secrets stay out of files that might be committed.
