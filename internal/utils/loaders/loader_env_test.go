package loaders_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/paerser/cli"
	"github.com/tinyauthapp/paerser/env"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/loaders"
)

func TestLoadRedactsDecodeErrorValue(t *testing.T) {
	secret := "super-secret-token-pasted-into-the-wrong-var"
	t.Setenv("TINYAUTH_SERVER_PORT", secret) // port is an int, so this value fails to decode

	loader := &loaders.EnvLoader{}
	cfg := model.NewDefaultConfiguration(model.RuntimeEnvUnknown)

	_, err := loader.Load(nil, &cli.Command{Configuration: cfg})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "TINYAUTH_SERVER_PORT")
	assert.NotContains(t, err.Error(), secret)
}

func TestUnknownEnvVars(t *testing.T) {
	cfg := model.NewDefaultConfiguration(model.RuntimeEnvUnknown)

	environ := []string{
		"PATH=/usr/bin",
		"APP_URL=https://tinyauth.example.com", // not prefixed, not ours
		"TINYAUTH_APPURL=https://tinyauth.example.com",
		"TINYAUTH_APP_URL=https://tinyauth.example.com",
		"TINYAUTH_SERVER_PORT=3000",
		"TINYAUTH_RESOURCESDIR=/data/resources", // matches the resources section, caught by InvalidEnvVars instead
		// injected by Kubernetes for a service named tinyauth
		"TINYAUTH_PORT=tcp://10.0.0.1:3000",
		"TINYAUTH_PORT_3000_TCP=tcp://10.0.0.1:3000",
		"TINYAUTH_PORT_3000_TCP_ADDR=10.0.0.1",
		"TINYAUTH_PORT_3000_TCP_PORT=3000",
		"TINYAUTH_PORT_3000_TCP_PROTO=tcp",
		"TINYAUTH_SERVICE_HOST=10.0.0.1",
		"TINYAUTH_SERVICE_PORT=3000",
		"TINYAUTH_SERVICE_PORT_HTTP=3000",
	}

	vars := env.FindPrefixedEnvVars(environ, model.DefaultNamePrefix, cfg)

	assert.Equal(t, []string{"TINYAUTH_APP_URL"}, loaders.UnknownEnvVars(environ, vars))
	assert.Empty(t, loaders.UnknownEnvVars([]string{"TINYAUTH_APPURL=https://tinyauth.example.com"}, []string{"TINYAUTH_APPURL=https://tinyauth.example.com"}))
}

func TestInvalidEnvVars(t *testing.T) {
	cfg := model.NewDefaultConfiguration(model.RuntimeEnvUnknown)

	vars := []string{
		"TINYAUTH_APPURL=https://tinyauth.example.com",
		"TINYAUTH_DATABASEPATH=/data/tinyauth.db",
		"TINYAUTH_DATABASEPATH=/data/tinyauth.db", // duplicates are reported once
		"TINYAUTH_SERVER_PORT=3000",
		"TINYAUTH_RESOURCESDIR=/data/resources",
		"TINYAUTH_OAUTH_PROVIDERS_GOOGLE_CLIENT_ID=abc",
		"TINYAUTH_OAUTH_PROVIDERS_GOOGLE_CLIENTID=abc",
	}

	assert.Equal(t, []string{"TINYAUTH_DATABASEPATH", "TINYAUTH_RESOURCESDIR", "TINYAUTH_OAUTH_PROVIDERS_GOOGLE_CLIENT_ID"}, loaders.InvalidEnvVars(vars, cfg))

	// The configuration passed in must not be modified
	assert.Equal(t, model.NewDefaultConfiguration(model.RuntimeEnvUnknown), cfg)

	assert.Nil(t, loaders.InvalidEnvVars(vars, nil))
}
