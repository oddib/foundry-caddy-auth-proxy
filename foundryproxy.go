package foundryauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

func init() {
	caddy.RegisterModule(FoundryProxy{})
	httpcaddyfile.RegisterHandlerDirective("foundry_proxy", parseFoundryProxy)
}

// User Schema Structures based on user.json
type WorldCreds struct {
	UserID   string `json:"userid"`
	Password string `json:"password"`
	Known    bool   `json:"known"`
}

type UserProfile struct {
	Worlds map[string]WorldCreds `json:"worlds"`
	Admin  bool                  `json:"admin"`
}

type UserStore struct {
	Users    map[string]UserProfile `json:"users"`
	AdminKey string                 `json:"adminkey"`
}

// FoundryProxy implements a Caddy handler that intercepts Foundry VTT auth.
type FoundryProxy struct {
	BackendURL    string `json:"backend_url"`
	UserStorePath string `json:"user_store_path"`
	HeaderName    string `json:"header_name"`

	store  UserStore
	proxy  *reverseproxy.Handler
	client *http.Client
}

// CaddyModule returns the Caddy module information.
func (FoundryProxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.foundry_proxy",
		New: func() caddy.Module { return &FoundryProxy{HeaderName: "X-Forwarded-User"} },
	}
}

// Provision sets up the module's internal state.
func (m *FoundryProxy) Provision(ctx caddy.Context) error {
	data, err := os.ReadFile(m.UserStorePath)
	if err != nil {
		return fmt.Errorf("failed to read user store: %v", err)
	}
	if err := json.Unmarshal(data, &m.store); err != nil {
		return fmt.Errorf("failed to parse user store JSON: %v", err)
	}

	m.client = &http.Client{Timeout: 3 * time.Second}

	// Set up the internal reverse proxy to the backend
	m.proxy = &reverseproxy.Handler{
		Upstreams: reverseproxy.UpstreamPool{{Dial: m.BackendURL}},
	}
	return m.proxy.Provision(ctx)
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (m *FoundryProxy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.NextArg() {
			return d.ArgErr()
		}
		m.BackendURL = d.Val()

		if !d.NextArg() {
			return d.ArgErr()
		}
		m.UserStorePath = d.Val()

		for d.NextBlock(0) {
			switch d.Val() {
			case "header_auth_name":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.HeaderName = d.Val()
			default:
				return d.Errf("unknown subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

func (m FoundryProxy) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	idpUser := r.Header.Get(m.HeaderName)
	profile, exists := m.store.Users[idpUser]

	// 1. Strict Access Control: No user in store = 403
	if !exists || idpUser == "" {
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("unauthorized idp user: %s", idpUser))
	}

	// 2. Hijack /auth (Admin Setup)
	if r.URL.Path == "/auth" {
		if !profile.Admin {
			return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("admin permissions required"))
		}
		r.Method = http.MethodPost
		payload := fmt.Sprintf("adminPassword=%s&action=adminAuth", m.store.AdminKey)
		m.rebuildRequest(r, payload, "application/x-www-form-urlencoded")
	}

	// 3. Hijack /join (World Authentication)
	if r.URL.Path == "/join" {
		worldID, active, err := m.getFoundryState()
		// If no world is active, Foundry is likely at the setup screen
		if err != nil || !active {
			http.Redirect(w, r, "/auth", http.StatusTemporaryRedirect)
			return nil
		}

		creds, ok := profile.Worlds[worldID]
		if !ok {
			return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("user %s not allowed in world %s", idpUser, worldID))
		}

		r.Method = http.MethodPost
		body, _ := json.Marshal(map[string]string{
			"userid":   creds.UserID,
			"password": creds.Password,
		})
		m.rebuildRequest(r, string(body), "application/json")
	}

	// 4. Response Interception (Redirect Loop Protection)
	rr := caddyhttp.NewResponseRecorder(w, nil, nil)

	err := m.proxy.ServeHTTP(rr, r, next)
	if err != nil {
		return err
	}

	statusCode := rr.Status()

	// Intercept redirects pointing back to auth/setup and force to /game
	if statusCode == http.StatusFound || statusCode == http.StatusSeeOther {
		location := rr.Header().Get("Location")
		if location == "/auth" || location == "/setup" {
			w.Header().Set("Location", "/game")
			w.WriteHeader(statusCode)
			return nil
		}
	}

	return rr.WriteResponse()
}

// getFoundryState queries the unauthenticated /api/status endpoint
func (m FoundryProxy) getFoundryState() (string, bool, error) {
	resp, err := m.client.Get(fmt.Sprintf("http://%s/api/status", m.BackendURL))
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	var status struct {
		Active bool   `json:"active"`
		World  string `json:"world"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return "", false, err
	}
	return status.World, status.Active, nil
}

// rebuildRequest wipes the request and reconstructs it for the hijacked auth call
func (m FoundryProxy) rebuildRequest(r *http.Request, payload string, contentType string) {
	r.Body = io.NopCloser(bytes.NewBufferString(payload))
	r.ContentLength = int64(len(payload))

	// Keep only essential headers for the session hand-off
	cookies := r.Header.Get("Cookie")
	ua := r.Header.Get("User-Agent")

	r.Header = make(http.Header)
	r.Header.Set("Content-Type", contentType)
	r.Header.Set("Content-Length", fmt.Sprintf("%d", len(payload)))

	if cookies != "" {
		r.Header.Set("Cookie", cookies)
	}
	if ua != "" {
		r.Header.Set("User-Agent", ua)
	}
}

// parseFoundryProxy configures the directive from the Caddyfile.
func parseFoundryProxy(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := new(FoundryProxy)
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var _ caddy.Provisioner = (*FoundryProxy)(nil)
var _ caddyfile.Unmarshaler = (*FoundryProxy)(nil)
var _ caddyhttp.MiddlewareHandler = (*FoundryProxy)(nil)
