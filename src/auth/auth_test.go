package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"hubproxy/config"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestFirstUseFixedExpirySurvivesRestart(t *testing.T) {
	s := testStore(t)
	now := time.Date(2026, 10, 12, 1, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	secret, token, err := s.Create("download", 3600)
	if err != nil {
		t.Fatal(err)
	}
	if token.ActivatedAt != nil {
		t.Fatal("creation activated token")
	}
	now = now.Add(24 * time.Hour)
	if err = s.Authorize(secret, false); err != nil {
		t.Fatal(err)
	}
	if s.List()[0].ActivatedAt != nil {
		t.Fatal("metadata request activated token")
	}
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Authorize(secret, true); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	want := now.Add(time.Hour)
	if !s.List()[0].ExpiresAt.Equal(want) {
		t.Fatal("wrong activation time")
	}
	now = now.Add(30 * time.Minute)
	if err = s.Authorize(secret, true); err != nil {
		t.Fatal(err)
	}
	if !s.List()[0].ExpiresAt.Equal(want) {
		t.Fatal("request extended expiry")
	}
	saved, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(saved), secret) {
		t.Fatal("plaintext credential persisted")
	}
	restarted, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = func() time.Time { return want }
	if err = restarted.Authorize(secret, true); err != ErrDenied {
		t.Fatalf("expiry boundary allowed request: %v", err)
	}
	if restarted.List()[0].ActivatedAt == nil {
		t.Fatal("activation lost at restart")
	}
}
func TestStoreFailsClosedOnSaveFailureAndCorruption(t *testing.T) {
	s := testStore(t)
	secret, _, err := s.Create("", 60)
	if err != nil {
		t.Fatal(err)
	}
	s.path = filepath.Join(s.path, "not-a-directory")
	if err = s.Authorize(secret, true); err == nil {
		t.Fatal("admitted request without durable activation")
	}
	if s.List()[0].ActivatedAt != nil {
		t.Fatal("failed activation not rolled back")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte("{broken"), 0600)
	if _, err := OpenStore(bad); err == nil {
		t.Fatal("accepted corrupt state")
	}
}
func testManager(t *testing.T) *Manager {
	t.Helper()
	m, err := New(config.AuthConfig{DataFile: filepath.Join(t.TempDir(), "tokens.json")}, "test-password-123456")
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func TestProxyGateAllEntrypointsAndCredentialIsolation(t *testing.T) {
	m := testManager(t)
	secret, _, _ := m.store.Create("", 60)
	var seen string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.RequestURI()
		if r.Header.Get("Cookie") != "" || r.Header.Get("Referer") != "" || r.Header.Get("Authorization") != "" {
			t.Error("credential leaked upstream")
		}
		if ProxyPrefix(r) != "/"+secret {
			t.Error("missing follow-up prefix")
		}
		w.Header().Set("Cache-Control", "public, max-age=9999")
		w.WriteHeader(200)
	})
	handler := m.Wrap(next)
	for _, path := range []string{"/https://github.com/a/b/releases/a", "/v2/library/nginx/manifests/latest", "/token?scope=repository:a:pull", "/api/search?q=a", "/api/image/download?image=a", "/api/image/batch?token=a", "/api/tags/library/nginx"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 403 {
			t.Fatalf("unprotected %s: %d", path, w.Code)
		}
	}
	for _, path := range []string{"/" + secret + "/https://github.com/a/b/releases/a?x=1", "/v2/" + secret + "/library/nginx/manifests/latest", "/" + secret + "/api/image/download?image=a"} {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Cookie", "hubproxy_admin=private")
		req.Header.Set("Referer", "https://example.com/"+secret)
		req.Header.Set("Authorization", "Bearer private")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != 200 || strings.Contains(seen, secret) {
			t.Fatalf("bad forwarding %s %d", seen, w.Code)
		}
		if w.Header().Get("Cache-Control") != "private, no-store" {
			t.Fatal("cache bypass possible")
		}
	}
	for _, suffix := range []string{"/api/admin/tokens", "/ready", "/assets/x.js"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "/"+secret+suffix, nil))
		if w.Code != 403 {
			t.Fatal("credential path reached public route")
		}
	}
}
func TestExpiryDoesNotInterruptExistingTransfer(t *testing.T) {
	m := testManager(t)
	secret, _, _ := m.store.Create("", 60)
	now := time.Now()
	m.store.now = func() time.Time { return now }
	handler := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now = now.Add(61 * time.Second)
		w.WriteHeader(200)
		io.WriteString(w, "complete")
	}))
	path := "/" + secret + "/https://github.com/a/b/releases/a"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	if w.Code != 200 || w.Body.String() != "complete" {
		t.Fatal("interrupted admitted transfer")
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	if w.Code != 403 {
		t.Fatal("expired request admitted")
	}
}
func TestAdminLoginCSRFAndTokenLifecycle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := testManager(t)
	router := gin.New()
	m.Register(router)
	var cookie *http.Cookie
	request := func(method, path, body string, csrf bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/admin/"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if csrf {
			r.Header.Set("X-Hubproxy-Admin", "1")
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "tokens", "", false); w.Code != 401 {
		t.Fatal("list without login")
	}
	if w := request("POST", "login", `{"password":"test-password-123456"}`, false); w.Code != 403 {
		t.Fatal("missing CSRF header accepted")
	}
	if w := request("POST", "login", `{"password":"wrong"}`, true); w.Code != 401 {
		t.Fatal("wrong password accepted")
	}
	w := request("POST", "login", `{"password":"test-password-123456"}`, true)
	if w.Code != 200 {
		t.Fatalf("login %d %s", w.Code, w.Body.String())
	}
	cookie = w.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/api/admin" {
		t.Fatal("unsafe cookie")
	}
	w = request("POST", "tokens", `{"name":"test"}`, true)
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	var result struct {
		Secret string `json:"secret"`
		Token  Token  `json:"token"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Token.DurationSeconds != 3600 || result.Token.ActivatedAt != nil {
		t.Fatal("bad default duration or activation")
	}
	if w = request("GET", "tokens", "", false); strings.Contains(w.Body.String(), result.Secret) {
		t.Fatal("list discloses token secret")
	}
	if w = request("DELETE", "tokens/"+result.Token.ID, "", true); w.Code != 204 {
		t.Fatal("delete failed")
	}
	if err := m.store.Authorize(result.Secret, true); err != ErrDenied {
		t.Fatal("deleted token accepted")
	}
	if w = request("POST", "logout", "", true); w.Code != 204 {
		t.Fatal("logout failed")
	}
	if w = request("GET", "tokens", "", false); w.Code != 401 {
		t.Fatal("session not invalidated")
	}
}
