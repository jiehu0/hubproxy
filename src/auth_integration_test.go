package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"hubproxy/config"
	"hubproxy/handlers"
	"hubproxy/utils"
)

func TestProtectedRegistryFullImagePull(t *testing.T) {
	// Serve a real two-layer OCI image from a local upstream. No external network needed.
	upstream := httptest.NewServer(registry.New())
	defer upstream.Close()
	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	image, err := random.Image(1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := name.NewTag(upstreamHost+"/test/image:latest", name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err = remote.Write(tag, image); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	body := fmt.Sprintf("[auth]\nenabled=true\ncookieSecure=false\ndataFile=%q\n[registries.\"ghcr.io\"]\nupstream=%q\nenabled=true\n", filepath.Join(dir, "tokens.json"), upstreamHost)
	if err = os.WriteFile(cfgPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_PATH", cfgPath)
	t.Setenv("AUTH_ENABLED", "true")
	t.Setenv("AUTH_ADMIN_PASSWORD", "integration-password-123")
	if err = config.LoadConfig(); err != nil {
		t.Fatal(err)
	}
	utils.InitHTTPClients()
	globalLimiter = utils.InitGlobalLimiter()
	handlers.InitDockerProxy()
	handlers.InitImageStreamer()
	handlers.InitDebouncer()
	handler, err := buildRouter(config.GetConfig())
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(handler)
	defer proxy.Close()
	request := func(method, path, body string, cookie *http.Cookie) *http.Response {
		t.Helper()
		r, _ := http.NewRequest(method, proxy.URL+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Hubproxy-Admin", "1")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	login := request("POST", "/api/admin/login", `{"password":"integration-password-123"}`, nil)
	login.Body.Close()
	if login.StatusCode != 200 {
		t.Fatal("login failed")
	}
	cookie := login.Cookies()[0]
	created := request("POST", "/api/admin/tokens", `{"duration_seconds":60}`, cookie)
	var issued struct {
		Secret string `json:"secret"`
		Token  struct {
			ID string `json:"id"`
		} `json:"token"`
	}
	json.NewDecoder(created.Body).Decode(&issued)
	created.Body.Close()
	if issued.Secret == "" {
		t.Fatal("no token")
	}
	source := strings.TrimPrefix(proxy.URL, "http://") + "/" + issued.Secret + "/ghcr.io/test/image:latest"
	pullRef, err := name.NewTag(source, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	pulled, err := remote.Image(pullRef)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, _ := image.Digest()
	gotDigest, err := pulled.Digest()
	if err != nil || gotDigest != wantDigest {
		t.Fatal("manifest changed")
	}
	// Read configuration and every compressed layer, as a complete pull does.
	wantConfig, _ := image.RawConfigFile()
	gotConfig, err := pulled.RawConfigFile()
	if err != nil || !bytes.Equal(gotConfig, wantConfig) {
		t.Fatal("config blob differs", err)
	}
	expected, _ := image.Layers()
	layers, err := pulled.Layers()
	if err != nil || len(layers) != 2 {
		t.Fatal("wrong layer count")
	}
	for i, layer := range layers {
		r, err := layer.Compressed()
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		wantReader, _ := expected[i].Compressed()
		want, _ := io.ReadAll(wantReader)
		wantReader.Close()
		if !bytes.Equal(got, want) {
			t.Fatal("layer corrupted")
		}
	}
	// A portal session must not bypass the proxy token requirement.
	unprotected := request("GET", "/v2/ghcr.io/test/image/manifests/latest", "", cookie)
	unprotected.Body.Close()
	if unprotected.StatusCode != 403 {
		t.Fatal("portal cookie bypassed gate")
	}
	prepared := request("GET", "/"+issued.Secret+"/api/image/download?image=nginx&mode=prepare", "", nil)
	var prep struct {
		URL string `json:"download_url"`
	}
	json.NewDecoder(prepared.Body).Decode(&prep)
	prepared.Body.Close()
	if !strings.HasPrefix(prep.URL, "/"+issued.Secret+"/api/image/download?") {
		t.Fatal("offline download lost proxy credential")
	}
	deleted := request("DELETE", "/api/admin/tokens/"+issued.Token.ID, "", cookie)
	deleted.Body.Close()
	if deleted.StatusCode != 204 {
		t.Fatal("delete failed")
	}
	if _, err = remote.Get(pullRef); err == nil {
		t.Fatal("deleted credential still permits pull")
	}
}

type rewriteTransport struct{ target string }

func (x rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	cloned := r.Clone(r.Context())
	cloned.URL.Scheme = "http"
	cloned.URL.Host = x.target
	return http.DefaultTransport.RoundTrip(cloned)
}

func TestProtectedFileDownloadRedirectAndRange(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" || strings.Contains(r.Header.Get("Referer"), "http://proxy/") {
			t.Error("portal credentials forwarded")
		}
		if strings.HasSuffix(r.URL.Path, "/redirect") {
			w.Header().Set("Location", "https://github.com/a/b/releases/file")
			w.WriteHeader(302)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "public,max-age=86400")
		w.Header().Set("Set-Cookie", "hubproxy_admin=attacker; Path=/api/admin")
		if r.Header.Get("Range") == "bytes=2-4" {
			w.Header().Set("Content-Range", "bytes 2-4/6")
			w.WriteHeader(206)
			io.WriteString(w, "cde")
			return
		}
		io.WriteString(w, "abcdef")
	}))
	defer upstream.Close()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgPath, []byte(fmt.Sprintf("[auth]\ndataFile=%q\ncookieSecure=false\n", filepath.Join(dir, "tokens.json"))), 0600)
	t.Setenv("CONFIG_PATH", cfgPath)
	t.Setenv("AUTH_ENABLED", "true")
	t.Setenv("AUTH_ADMIN_PASSWORD", "integration-password-123")
	if err := config.LoadConfig(); err != nil {
		t.Fatal(err)
	}
	utils.InitHTTPClients()
	globalLimiter = utils.InitGlobalLimiter()
	handlers.InitDockerProxy()
	client := utils.GetGlobalHTTPClient()
	old := client.Transport
	client.Transport = rewriteTransport{strings.TrimPrefix(upstream.URL, "http://")}
	defer func() { client.Transport = old }()
	handler, err := buildRouter(config.GetConfig())
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRequest("POST", "/api/admin/login", strings.NewReader(`{"password":"integration-password-123"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("X-Hubproxy-Admin", "1")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, login)
	cookie := w.Result().Cookies()[0]
	create := httptest.NewRequest("POST", "/api/admin/tokens", strings.NewReader(`{}`))
	create.Header = login.Header.Clone()
	create.AddCookie(cookie)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, create)
	var issued struct {
		Secret string `json:"secret"`
	}
	json.Unmarshal(w.Body.Bytes(), &issued)
	if issued.Secret == "" {
		t.Fatal("create failed")
	}
	for _, test := range []struct {
		suffix, rangeHeader, body string
		status                    int
	}{{"file", "", "abcdef", 200}, {"file", "bytes=2-4", "cde", 206}, {"redirect", "", "abcdef", 200}} {
		r := httptest.NewRequest("GET", "/"+issued.Secret+"/https://github.com/a/b/releases/"+test.suffix, nil)
		r.Header.Set("Range", test.rangeHeader)
		r.Header.Set("Referer", "http://proxy/"+issued.Secret)
		r.AddCookie(cookie)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != test.status || w.Body.String() != test.body {
			t.Fatalf("download status/body: %d %q", w.Code, w.Body.String())
		}
		if len(w.Result().Cookies()) != 0 || w.Header().Get("Cache-Control") != "private, no-store" {
			t.Fatal("unsafe upstream headers")
		}
		if w.Header().Get("Content-Security-Policy") == "" {
			t.Fatal("untrusted content not sandboxed")
		}
		if test.status == 302 && !strings.HasPrefix(w.Header().Get("Location"), "/"+issued.Secret+"/") {
			t.Fatal("redirect lost credential")
		}
	}
	// Also verify the explicit redirect branch when the upstream client leaves redirects to the handler.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	r := httptest.NewRequest("GET", "/"+issued.Secret+"/https://github.com/a/b/releases/redirect", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 302 || !strings.HasPrefix(w.Header().Get("Location"), "/"+issued.Secret+"/") {
		t.Fatal("redirect lost proxy credential")
	}

}
