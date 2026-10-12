package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"hubproxy/config"
)

const cookieName = "hubproxy_admin"

type prefixKey struct{}

// ProxyPrefix preserves the credential when producing follow-up download URLs.
func ProxyPrefix(r *http.Request) string {
	p, _ := r.Context().Value(prefixKey{}).(string)
	return p
}

type Manager struct {
	store        *Store
	passwordHash []byte
	cookieSecure bool
	mu           sync.Mutex
	sessions     map[string]time.Time
	loginLimit   *rate.Limiter
}

func New(cfg config.AuthConfig, password string) (*Manager, error) {
	if len(password) < 12 || len(password) > 72 {
		return nil, errors.New("AUTH_ADMIN_PASSWORD must contain 12–72 bytes")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	s, err := OpenStore(cfg.DataFile)
	if err != nil {
		return nil, err
	}
	return &Manager{store: s, passwordHash: hash, cookieSecure: cfg.CookieSecure,
		sessions: make(map[string]time.Time), loginLimit: rate.NewLimiter(rate.Every(5*time.Second), 5)}, nil
}

func (m *Manager) authenticated(c *gin.Context) bool {
	value, err := c.Cookie(cookieName)
	if err != nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id := digest(value)
	expires, ok := m.sessions[id]
	if !ok || !time.Now().Before(expires) {
		delete(m.sessions, id)
		return false
	}
	return true
}

func (m *Manager) cookie(c *gin.Context, value string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{Name: cookieName, Value: value, Path: "/api/admin", MaxAge: maxAge,
		HttpOnly: true, Secure: m.cookieSecure, SameSite: http.SameSiteStrictMode})
}

func (m *Manager) Register(router *gin.Engine) {
	admin := router.Group("/api/admin")
	admin.Use(func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("Referrer-Policy", "no-referrer")
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
		// Custom header + no CORS prevents cross-origin form or fetch mutations.
		if c.Request.Method != http.MethodGet {
			if c.GetHeader("X-Hubproxy-Admin") != "1" {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			if origin := c.GetHeader("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || u.Host != c.Request.Host {
					c.AbortWithStatus(http.StatusForbidden)
					return
				}
			}
		}
	})
	admin.GET("session", func(c *gin.Context) { c.JSON(200, gin.H{"enabled": true, "authenticated": m.authenticated(c)}) })
	admin.POST("login", func(c *gin.Context) {
		if !m.loginLimit.Allow() {
			c.Header("Retry-After", "5")
			c.JSON(429, gin.H{"error": "尝试过于频繁，请稍后重试"})
			return
		}
		var body struct {
			Password string `json:"password"`
		}
		if c.ShouldBindJSON(&body) != nil {
			c.JSON(400, gin.H{"error": "请求格式错误"})
			return
		}
		if bcrypt.CompareHashAndPassword(m.passwordHash, []byte(body.Password)) != nil {
			c.JSON(401, gin.H{"error": "密码错误"})
			return
		}
		value, err := randomSecret()
		if err != nil {
			c.Status(500)
			return
		}
		m.mu.Lock()
		for id, exp := range m.sessions {
			if time.Now().After(exp) {
				delete(m.sessions, id)
			}
		}
		if len(m.sessions) >= 100 {
			m.mu.Unlock()
			c.JSON(429, gin.H{"error": "登录会话已达上限"})
			return
		}
		m.sessions[digest(value)] = time.Now().Add(12 * time.Hour)
		m.mu.Unlock()
		m.cookie(c, value, 43200)
		c.JSON(200, gin.H{"authenticated": true})
	})
	admin.Use(func(c *gin.Context) {
		if !m.authenticated(c) {
			c.AbortWithStatusJSON(401, gin.H{"error": "请先登录"})
		}
	})
	admin.POST("logout", func(c *gin.Context) {
		value, _ := c.Cookie(cookieName)
		m.mu.Lock()
		delete(m.sessions, digest(value))
		m.mu.Unlock()
		m.cookie(c, "", -1)
		c.Status(204)
	})
	admin.GET("tokens", func(c *gin.Context) { c.JSON(200, m.store.List()) })
	admin.POST("tokens", func(c *gin.Context) {
		var body struct {
			Name            string `json:"name"`
			DurationSeconds int64  `json:"duration_seconds"`
		}
		if c.ShouldBindJSON(&body) != nil || len(body.Name) > 120 {
			c.JSON(400, gin.H{"error": "请输入有效名称与时长"})
			return
		}
		if body.DurationSeconds == 0 {
			body.DurationSeconds = 3600
		}
		if body.DurationSeconds < 60 || body.DurationSeconds > 2592000 {
			c.JSON(400, gin.H{"error": "有效时长应在 1 分钟至 30 天之间"})
			return
		}
		secret, token, err := m.store.Create(strings.TrimSpace(body.Name), body.DurationSeconds)
		if err != nil {
			c.JSON(500, gin.H{"error": "无法保存令牌"})
			return
		}
		c.JSON(201, gin.H{"secret": secret, "token": token})
	})
	admin.DELETE("tokens/:id", func(c *gin.Context) {
		if err := m.store.Delete(c.Param("id")); err != nil {
			if errors.Is(err, ErrDenied) {
				c.Status(404)
			} else {
				c.Status(500)
			}
			return
		}
		c.Status(204)
	})
}

// Protected responses must not be served from a public/browser cache after expiry.
type privateWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *privateWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Del("Set-Cookie")
	w.ResponseWriter.WriteHeader(code)
}
func (w *privateWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(p)
}
func (w *privateWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(200)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}
func (w *privateWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func deny(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	fmt.Fprint(w, `{"error":"令牌缺失、无效或已过期","errors":[{"code":"DENIED","message":"proxy token required or expired"}]}`)
}

func (m *Manager) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		// Only UI assets, management routes, health, and a data-free Docker ping are public.
		if path == "/" || path == "/admin" || path == "/images" || path == "/search" || path == "/favicon.ico" ||
			strings.HasPrefix(path, "/assets/") || strings.HasPrefix(path, "/api/admin/") || path == "/ready" {
			w.Header().Set("Referrer-Policy", "no-referrer")
			next.ServeHTTP(w, r)
			return
		}
		if path == "/v2/" || path == "/v2" {
			w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, "{}")
			return
		}
		var secret, rest string
		var found bool
		if strings.HasPrefix(path, "/v2/") {
			secret, rest, found = strings.Cut(strings.TrimPrefix(path, "/v2/"), "/")
			rest = "/v2/" + rest
		} else {
			secret, rest, found = strings.Cut(strings.TrimPrefix(path, "/"), "/")
			rest = "/" + rest
		}
		if !found {
			deny(w, 403)
			return
		}
		// Token-prefixed UI/admin paths are not proxy operations and must not activate a token.
		if rest == "/" || rest == "/ready" || strings.HasPrefix(rest, "/api/admin") || strings.HasPrefix(rest, "/assets/") || rest == "/admin" || rest == "/images" || rest == "/search" || rest == "/favicon.ico" {
			deny(w, 403)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "POST" {
			deny(w, 405)
			return
		}
		// Browsing search/info is authenticated but does not start the download clock.
		activate := !(rest == "/api/search" || strings.HasPrefix(rest, "/api/tags/") || rest == "/api/image/info")
		if err := m.store.Authorize(secret, activate); err != nil {
			if errors.Is(err, ErrDenied) {
				deny(w, 403)
			} else {
				deny(w, 503)
			}
			return
		}
		cloned := r.Clone(context.WithValue(r.Context(), prefixKey{}, "/"+secret))
		cloned.URL.Path, cloned.URL.RawPath = rest, ""
		cloned.RequestURI = cloned.URL.RequestURI()
		// Never forward the portal cookie or a token-bearing referrer to an upstream.
		for _, h := range []string{"Cookie", "Authorization", "Proxy-Authorization", "Referer", "Origin", "X-Hubproxy-Admin"} {
			cloned.Header.Del(h)
		}
		next.ServeHTTP(&privateWriter{ResponseWriter: w}, cloned)
	})
}
