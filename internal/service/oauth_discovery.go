package service

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/model"
)

// oidcDiscoveryDocument holds the endpoints Tinyauth can fill from an OIDC provider's well-known
// configuration (https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).
type oidcDiscoveryDocument struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

// resolveOIDCDiscovery fills any OAuth endpoint (authorization, token, userinfo) left empty from the
// provider's OIDC discovery document when an issuer is configured. Explicitly configured endpoints are
// never overwritten, so a provider with all endpoints set (or no issuer) is returned unchanged and the
// behaviour stays backwards compatible. It fails soft: on any error the original config is returned with
// the error, so startup continues and the existing "missing endpoint" handling surfaces later.
func resolveOIDCDiscovery(cfg model.OAuthServiceConfig, ctx context.Context) (model.OAuthServiceConfig, error) {
	if cfg.Issuer == "" {
		return cfg, nil
	}

	if cfg.AuthURL != "" && cfg.TokenURL != "" && cfg.UserinfoURL != "" {
		return cfg, nil
	}

	url := strings.TrimRight(cfg.Issuer, "/") + "/.well-known/openid-configuration"

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.Insecure,
				MinVersion:         tls.VersionTLS12,
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

	if err != nil {
		return cfg, fmt.Errorf("failed to build OIDC discovery request: %w", err)
	}

	resp, err := client.Do(req)

	if err != nil {
		return cfg, fmt.Errorf("failed to fetch OIDC discovery document: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return cfg, fmt.Errorf("OIDC discovery document returned status %d", resp.StatusCode)
	}

	var doc oidcDiscoveryDocument

	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return cfg, fmt.Errorf("failed to decode OIDC discovery document: %w", err)
	}

	if cfg.AuthURL == "" {
		cfg.AuthURL = doc.AuthorizationEndpoint
	}

	if cfg.TokenURL == "" {
		cfg.TokenURL = doc.TokenEndpoint
	}

	if cfg.UserinfoURL == "" {
		cfg.UserinfoURL = doc.UserinfoEndpoint
	}

	return cfg, nil
}
