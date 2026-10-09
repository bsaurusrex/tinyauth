package loaders

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/tinyauthapp/paerser/cli"
	"github.com/tinyauthapp/paerser/env"
	"github.com/tinyauthapp/tinyauth/internal/model"
)

// kubernetesServiceEnvVar matches the variables Kubernetes injects for a service named tinyauth (service links)
var kubernetesServiceEnvVar = regexp.MustCompile(`^TINYAUTH_(SERVICE_HOST|SERVICE_PORT(_[A-Z0-9_]+)?|PORT(_[0-9]+_(TCP|UDP|SCTP)(_(ADDR|PORT|PROTO))?)?)$`)

type EnvLoader struct {
	// Ignored holds the prefixed environment variables that matched no configuration option, they are logged on startup
	Ignored []string
}

func (e *EnvLoader) Load(_ []string, cmd *cli.Command) (bool, error) {
	environ := os.Environ()
	vars := env.FindPrefixedEnvVars(environ, model.DefaultNamePrefix, cmd.Configuration)
	e.Ignored = UnknownEnvVars(environ, vars)

	if len(vars) == 0 {
		return false, nil
	}

	if err := env.Decode(vars, model.DefaultNamePrefix, cmd.Configuration); err != nil {
		// The decoder error can echo the offending value (e.g. a strconv parse error), which may be a
		// secret pasted into the wrong variable, so it is not propagated. The rejected variable names
		// are reported instead, which is what the operator needs to fix it.
		if invalid := InvalidEnvVars(vars, cmd.Configuration); len(invalid) > 0 {
			return false, fmt.Errorf("failed to decode configuration from environment variables, check %s", strings.Join(invalid, ", "))
		}
		return false, errors.New("failed to decode configuration from environment variables")
	}

	return true, nil
}

// UnknownEnvVars returns the names of prefixed environment variables that do not map to any configuration
// section and are therefore silently ignored by the decoder (e.g. TINYAUTH_APP_URL instead of TINYAUTH_APPURL).
func UnknownEnvVars(environ []string, matched []string) []string {
	var unknown []string

	for _, value := range environ {
		if !strings.HasPrefix(value, model.DefaultNamePrefix) || slices.Contains(matched, value) {
			continue
		}
		name, _, _ := strings.Cut(value, "=")
		if kubernetesServiceEnvVar.MatchString(name) {
			continue
		}
		unknown = append(unknown, name)
	}

	return unknown
}

// InvalidEnvVars decodes each variable on its own into a fresh configuration to find the names the decoder rejects,
// since the decoder error only contains the failing node (e.g. "databasepath") and not the variable name.
func InvalidEnvVars(vars []string, configuration any) []string {
	var invalid []string

	cfgType := reflect.TypeOf(configuration)
	if cfgType == nil || cfgType.Kind() != reflect.Pointer {
		return nil
	}

	for _, value := range vars {
		fresh := reflect.New(cfgType.Elem()).Interface()
		if err := env.Decode([]string{value}, model.DefaultNamePrefix, fresh); err != nil {
			name, _, _ := strings.Cut(value, "=")
			if !slices.Contains(invalid, name) {
				invalid = append(invalid, name)
			}
		}
	}

	return invalid
}
