package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
)

func discoveryTestServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestResolveOIDCDiscovery(t *testing.T) {
	t.Run("no issuer is returned unchanged", func(t *testing.T) {
		cfg := model.OAuthServiceConfig{ClientID: "abc"}

		got, err := resolveOIDCDiscovery(cfg, context.Background())

		require.NoError(t, err)
		assert.Equal(t, cfg, got)
	})

	t.Run("fills missing endpoints from the discovery document", func(t *testing.T) {
		server := discoveryTestServer(t, http.StatusOK, `{
			"authorization_endpoint": "https://idp.example.com/authorize",
			"token_endpoint": "https://idp.example.com/token",
			"userinfo_endpoint": "https://idp.example.com/userinfo"
		}`)

		cfg := model.OAuthServiceConfig{Issuer: server.URL}

		got, err := resolveOIDCDiscovery(cfg, context.Background())

		require.NoError(t, err)
		assert.Equal(t, "https://idp.example.com/authorize", got.AuthURL)
		assert.Equal(t, "https://idp.example.com/token", got.TokenURL)
		assert.Equal(t, "https://idp.example.com/userinfo", got.UserinfoURL)
	})

	t.Run("does not overwrite explicitly configured endpoints", func(t *testing.T) {
		server := discoveryTestServer(t, http.StatusOK, `{
			"authorization_endpoint": "https://idp.example.com/authorize",
			"token_endpoint": "https://idp.example.com/token",
			"userinfo_endpoint": "https://idp.example.com/userinfo"
		}`)

		cfg := model.OAuthServiceConfig{
			Issuer:   server.URL,
			AuthURL:  "https://custom.example.com/auth",
			TokenURL: "https://custom.example.com/token",
			// UserinfoURL is left empty, so only it should be filled
		}

		got, err := resolveOIDCDiscovery(cfg, context.Background())

		require.NoError(t, err)
		assert.Equal(t, "https://custom.example.com/auth", got.AuthURL)
		assert.Equal(t, "https://custom.example.com/token", got.TokenURL)
		assert.Equal(t, "https://idp.example.com/userinfo", got.UserinfoURL)
	})

	t.Run("skips discovery when all endpoints are already set", func(t *testing.T) {
		// The issuer points at a server that always errors; discovery must not be attempted.
		server := discoveryTestServer(t, http.StatusInternalServerError, "boom")

		cfg := model.OAuthServiceConfig{
			Issuer:      server.URL,
			AuthURL:     "https://custom.example.com/auth",
			TokenURL:    "https://custom.example.com/token",
			UserinfoURL: "https://custom.example.com/userinfo",
		}

		got, err := resolveOIDCDiscovery(cfg, context.Background())

		require.NoError(t, err)
		assert.Equal(t, cfg, got)
	})

	t.Run("fails soft on a non-200 response", func(t *testing.T) {
		server := discoveryTestServer(t, http.StatusNotFound, "not found")

		cfg := model.OAuthServiceConfig{Issuer: server.URL}

		got, err := resolveOIDCDiscovery(cfg, context.Background())

		require.Error(t, err)
		assert.Empty(t, got.AuthURL)
		assert.Empty(t, got.TokenURL)
		assert.Empty(t, got.UserinfoURL)
	})

	t.Run("fails soft on an invalid document", func(t *testing.T) {
		server := discoveryTestServer(t, http.StatusOK, "not json")

		cfg := model.OAuthServiceConfig{Issuer: server.URL}

		got, err := resolveOIDCDiscovery(cfg, context.Background())

		require.Error(t, err)
		assert.Empty(t, got.AuthURL)
	})

	t.Run("fails soft on an oversized body instead of exhausting memory", func(t *testing.T) {
		// Pad the document past the read cap so the body cannot be fully consumed; the truncated
		// read must surface as a decode error rather than an unbounded allocation.
		padding := strings.Repeat(" ", (2<<20)+1)
		body := `{"authorization_endpoint": "https://idp.example.com/authorize"` + padding + `}`
		server := discoveryTestServer(t, http.StatusOK, body)

		cfg := model.OAuthServiceConfig{Issuer: server.URL}

		got, err := resolveOIDCDiscovery(cfg, context.Background())

		require.Error(t, err)
		assert.Empty(t, got.AuthURL)
	})
}
