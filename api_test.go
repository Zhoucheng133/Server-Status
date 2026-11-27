package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"golang.org/x/crypto/bcrypt"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	store, err := openStore(filepath.Join(dir, "data", "database.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.db.Close() })
	s := &Service{store: store, logDir: dir, logWake: make(chan struct{}, 1)}
	if err := s.loadSigningKey(); err != nil {
		t.Fatal(err)
	}
	return s
}

func callAPI(t *testing.T, app *fiber.App, method, path, token string, body, output any, status int) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != status {
		t.Fatalf("%s %s: got %d, want %d", method, path, resp.StatusCode, status)
	}
	if output != nil {
		if err := json.NewDecoder(resp.Body).Decode(output); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSingleAccountAndRefreshRotation(t *testing.T) {
	s := newTestService(t)
	app := fiber.New()
	s.registerRoutes(app)
	auth := authRequest{Username: "a", Password: "1"}
	var first, renewed tokenPair
	var status struct {
		NeedsSetup bool `json:"needs_setup"`
	}
	callAPI(t, app, "GET", "/api/status", "", nil, &status, 200)
	if !status.NeedsSetup {
		t.Fatal("new installation should allow registration")
	}
	callAPI(t, app, "POST", "/api/auth/register", "", authRequest{Password: auth.Password}, nil, 400)
	callAPI(t, app, "POST", "/api/auth/register", "", authRequest{Username: auth.Username}, nil, 400)
	callAPI(t, app, "POST", "/api/auth/register", "", auth, &first, 201)
	callAPI(t, app, "POST", "/api/auth/register", "", auth, nil, 409)
	callAPI(t, app, "POST", "/api/auth/login", "", authRequest{Username: auth.Username, Password: "wrong"}, nil, 401)
	callAPI(t, app, "POST", "/api/auth/login", "", auth, nil, 200)
	callAPI(t, app, "GET", "/api/status", "", nil, &status, 200)
	if status.NeedsSetup {
		t.Fatal("registration should be closed")
	}
	var hash string
	if err := s.store.db.QueryRow("SELECT password_hash FROM users").Scan(&hash); err != nil {
		t.Fatal(err)
	}
	bcryptHash, hasPrefix := strings.CutPrefix(hash, "bcrypt-sha256:")
	if !hasPrefix {
		t.Fatal("new account lacks a password hash format marker")
	}
	if _, err := bcrypt.Cost([]byte(bcryptHash)); err != nil {
		t.Fatalf("stored password is not a bcrypt hash: %v", err)
	}
	for _, path := range []string{"/api/live", "/api/ips", "/api/log-sources", "/api/auth/me"} {
		callAPI(t, app, "GET", path, "", nil, nil, 401)
	}
	callAPI(t, app, "GET", "/api/ips", first.RefreshToken, nil, nil, 401)
	callAPI(t, app, "POST", "/api/auth/refresh", "", authRequest{RefreshToken: first.RefreshToken}, &renewed, 200)
	callAPI(t, app, "POST", "/api/auth/refresh", "", authRequest{RefreshToken: first.RefreshToken}, nil, 401)
	callAPI(t, app, "GET", "/api/auth/me", renewed.AccessToken, nil, nil, 200)
	callAPI(t, app, "POST", "/api/auth/logout", "", authRequest{RefreshToken: renewed.RefreshToken}, nil, 204)
	callAPI(t, app, "POST", "/api/auth/refresh", "", authRequest{RefreshToken: renewed.RefreshToken}, nil, 401)

	const path = "/api/settings/log-sources"
	if err := os.WriteFile(filepath.Join(s.logDir, "example.org.json"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	type selection struct {
		Sources []string `json:"sources"`
	}
	ok := selection{[]string{"example.org.json"}}
	callAPI(t, app, "PUT", path, "", ok, nil, 401)
	callAPI(t, app, "PUT", path, first.AccessToken, selection{}, nil, 400)
	callAPI(t, app, "PUT", path, first.AccessToken, selection{[]string{"missing.json"}}, nil, 400)
	callAPI(t, app, "PUT", path, first.AccessToken, ok, nil, 200)
	var me struct {
		Configured bool
		Sources    []string `json:"log_sources"`
	}
	callAPI(t, app, "GET", "/api/auth/me", first.AccessToken, nil, &me, 200)
	if !me.Configured || len(me.Sources) != 1 || me.Sources[0] != ok.Sources[0] {
		t.Fatalf("unexpected settings: %+v", me)
	}
}

func TestLongUnicodeCredentialsPreserveAllCharacters(t *testing.T) {
	s := newTestService(t)
	app := fiber.New()
	s.registerRoutes(app)
	prefix := strings.Repeat("密", 24) // 72 UTF-8 bytes
	auth := authRequest{Username: " " + strings.Repeat("名", 65) + " ", Password: prefix + " 甲 "}
	var pair tokenPair
	callAPI(t, app, "POST", "/api/auth/register", "", auth, &pair, 201)
	var me struct{ Username string }
	callAPI(t, app, "GET", "/api/auth/me", pair.AccessToken, nil, &me, 200)
	if me.Username != auth.Username {
		t.Fatalf("stored username %q differs from registered username %q", me.Username, auth.Username)
	}
	callAPI(t, app, "POST", "/api/auth/login", "", auth, nil, 200)
	callAPI(t, app, "POST", "/api/auth/login", "", authRequest{Username: strings.TrimSpace(auth.Username), Password: auth.Password}, nil, 401)
	callAPI(t, app, "POST", "/api/auth/login", "", authRequest{Username: auth.Username, Password: prefix + " 乙 "}, nil, 401)
	callAPI(t, app, "POST", "/api/auth/login", "", authRequest{Username: auth.Username, Password: strings.TrimSpace(auth.Password)}, nil, 401)
}

func TestLoginWithLegacyBcryptPassword(t *testing.T) {
	s := newTestService(t)
	app := fiber.New()
	s.registerRoutes(app)
	auth := authRequest{Username: "owner", Password: strings.Repeat("a", 72)}
	hash, err := bcrypt.GenerateFromPassword([]byte(auth.Password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.store.db.Exec(`INSERT INTO users (id, username, password_hash, created_at) VALUES (1, ?, ?, ?)`, auth.Username, string(hash), time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	callAPI(t, app, "POST", "/api/auth/login", "", authRequest{Username: auth.Username, Password: auth.Password + "!"}, nil, 401)
	callAPI(t, app, "POST", "/api/auth/login", "", auth, nil, 200)
}

func TestPublicSiteCountsAndRetention(t *testing.T) {
	s := newTestService(t)
	app := fiber.New()
	s.registerRoutes(app)
	now := time.Now()
	for _, bucket := range []time.Time{now.Truncate(sampleInterval), now.Add(-25 * time.Hour)} {
		_, err := s.store.db.Exec(`INSERT INTO traffic_buckets VALUES (?, 'a.example', 5), (?, 'b.example', 7)`, bucket.Unix(), bucket.Unix())
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.store.db.Exec(`INSERT INTO ip_buckets VALUES (?, '192.0.2.1','US',12)`, bucket.Unix())
		if err != nil {
			t.Fatal(err)
		}
		if err := s.saveMetric(MetricSample{Timestamp: bucket.UTC().Format(time.RFC3339), CPU: 25, Memory: 50, NetworkIn: 100, NetworkOut: 10}); err != nil {
			t.Fatal(err)
		}
	}
	for path, want := range map[string]int64{"/api/overview": 12, "/api/overview?site=b.example": 7} {
		var data struct {
			Metrics   []MetricSample
			Requests  []TrafficSample
			Countries []CountryCount
			Sites     []string
			RecentIPs json.RawMessage `json:"recent_ips"`
		}
		callAPI(t, app, http.MethodGet, path, "", nil, &data, 200)
		if len(data.Metrics) != 1 || len(data.Requests) != 1 || data.Requests[0].Count != want || len(data.Sites) != 2 || len(data.Countries) != 1 || data.Countries[0].Count != 12 || data.RecentIPs != nil {
			t.Fatalf("unexpected overview: %+v", data)
		}
	}
	if err := s.store.prune(now); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"metric_samples", "ip_buckets", "traffic_buckets"} {
		var old int
		if err := s.store.db.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE ts < ?", now.Add(-24*time.Hour).Unix()).Scan(&old); err != nil || old != 0 {
			t.Fatalf("prune %s: old=%d, err=%v", table, old, err)
		}
	}
}

func TestConcurrentRegistrationCreatesOneAccount(t *testing.T) {
	s := newTestService(t)
	app := fiber.New()
	s.registerRoutes(app)
	credentials := []byte(`{"username":"owner","password":"testing password"}`)
	start := make(chan struct{})
	type response struct {
		status int
		err    error
	}
	replies := make(chan response, 2)
	for range 2 {
		go func() {
			req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewReader(credentials))
			req.Header.Set("Content-Type", "application/json")
			<-start
			res, err := app.Test(req)
			if err != nil {
				replies <- response{err: err}
				return
			}
			res.Body.Close()
			replies <- response{status: res.StatusCode}
		}()
	}
	close(start)
	counts := map[int]int{}
	for range 2 {
		reply := <-replies
		if reply.err != nil {
			t.Fatal(reply.err)
		}
		counts[reply.status]++
	}
	if counts[201] != 1 || counts[409] != 1 {
		t.Fatalf("concurrent registration: %v", counts)
	}
}
