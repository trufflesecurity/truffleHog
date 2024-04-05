package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-logr/logr"
	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ interface {
	detectors.Detector
	detectors.MaxSecretSizeProvider
} = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	keyPat          = regexp.MustCompile(`{(?:\s|\\[nrt])*\\?"auths\\?"(?:\s|\\t)*:(?:\s|\\t)*{(?:\s|\\[nrt])*\\?"(?i:https?:\/\/)?[a-z0-9\-.:\/]+\\?"(?:\s|\\t)*:(?:\s|\\t)*{(?:(?:\s|\\[nrt])*\\?"(?i:auth|email|username|password)\\?"\s*:\s*\\?".*\\?"\s*,?)+?(?:\s|\\[nrt])*}(?:\s|\\[nrt])*}(?:\s|\\[nrt])*}`)
	escapedReplacer = strings.NewReplacer(
		`\n`, "",
		`\r`, "",
		`\t`, "",
		`\"`, `"`,
	)

	// Common false-positives used in examples.
	exampleRegistries = map[string]struct{}{
		"https://index.docker.io/v1/":       {}, // https://github.com/moby/moby/blob/34679e568a22b4f35ff8460f3b5b7bf7089df818/cliconfig/config_test.go#L259
		"registry.hostname.com":             {}, // https://github.com/openshift/machine-config-operator/blob/82011335dbdd3d4c869b959d6048a3fba7742e47/pkg/controller/build/helpers_test.go#L47
		"registry.example.com:5000":         {}, // https://github.com/openshift/cluster-baremetal-operator/blob/f908020b1d46667056f21cf1d79e032c535a41fc/provisioning/baremetal_secrets_test.go#L53
		"registry2.example.com:5000":        {},
		"your.private.registry.example.com": {}, // https://github.com/kubernetes/website/blob/d130f326758988553c42179c087bfeec5bf948a0/content/en/docs/tasks/configure-pod-container/pull-image-private-registry.md?plain=1#L167
	}
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{`"auths"`, `\"auths\"`}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Docker
}

func (s Scanner) Description() string {
	return "Docker credentials can be used to pull images from private registries."
}

func (s Scanner) MaxSecretSize() int64 {
	return 4096
}

// FromData will find and optionally verify Docker secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	logCtx := logContext.AddLogger(ctx)
	logger := logCtx.Logger().WithName("docker")

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[0]] = struct{}{}
	}

	for match := range uniqueMatches {
		// Remove escaped quotes and literal whitespace characters, if present.
		// It is common for auth to be escaped, however, the json package cannot unmarshal escaped JSON.
		match := escapedReplacer.Replace(match)

		// Unmarshal the config string.
		// Doing byte->string->byte probably isn't the most efficient.
		var auths dockerAuths
		if err := json.NewDecoder(strings.NewReader(match)).Decode(&auths); err != nil {
			logger.Error(err, "Could not parse Docker auth JSON")
			return results, err
		} else if len(auths.Auths) == 0 {
			continue
		}

		for registry, auth := range auths.Auths {
			registry := registry
			// `docker.io` is a special case, Docker is hard-coded to rewrite it as `index.docker.io`.
			// https://github.com/moby/moby/blob/145a73a36c171b34c196ad780e699b154ddf47b5/registry/config_test.go#L329
			if strings.EqualFold(registry, "docker.io") {
				registry = "index.docker.io"
			}

			// Skip known invalid registries.
			if _, ok := exampleRegistries[registry]; ok {
				continue
			}

			// Skip configs with no credentials.
			// TODO: Should this be an error? What if it's a logic issue?
			username, password, b64encoded := parseBasicAuth(logger, auth)
			if username == "" && password == "" {
				// fmt.Printf("Skipping empty credentials: auth=%v, username='%s', password='%s'\n", auth, username, password)
				continue
			}

			r := detectors.Result{
				DetectorType: detectorspb.DetectorType_Docker,
				Raw:          []byte(b64encoded),
				RawV2:        []byte(`{"registry":"` + registry + `","auth":"` + b64encoded + `"}`),
				ExtraData:    map[string]string{"Registry": registry, "Username": username},
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := verifyMatch(logCtx, client, registry, username, b64encoded)
				r.Verified = isVerified
				r.SetVerificationError(verificationErr, match)
			}

			results = append(results, r)
		}
	}

	return
}

func verifyMatch(ctx logContext.Context, client *http.Client, registry string, username string, basicAuth string) (bool, error) {
	// Build the registry URL path.
	var registryUrl string
	registry, _ = strings.CutSuffix(registry, "/")
	if strings.HasPrefix(registry, "http://") || strings.HasPrefix(registry, "https://") {
		registryUrl = registry + "/v2/"
	} else {
		registryUrl = "https://" + registry + "/v2/"
	}

	// Build the request.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, registryUrl, nil)
	if err != nil {
		return false, nil
	}

	req.Header.Set("Authorization", "Basic "+basicAuth)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	// Send the initial request.
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	// Handle the initial response.
	switch res.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return false, err
		}

		return json.Valid(body), nil
	case http.StatusUnauthorized:
		// Some registries do not support basic auth, so we must follow the `Www-Authenticate` header, if present.
		// https://distribution.github.io/distribution/spec/auth/token/
		h := res.Header.Get("Www-Authenticate")
		if h == "" {
			return false, nil
		}

		if !strings.HasPrefix(h, "Bearer") {
			return false, fmt.Errorf("unsupported WWW-Authenticate auth scheme: %s", h)
		}

		authParams, err := parseAuthenticateHeader(h)
		if err != nil {
			return false, fmt.Errorf("failed to parse registry auth header: %w", err)
		}
		realm := authParams["realm"]
		if realm == "" {
			return false, fmt.Errorf("unexpected empty realm for WWW-Authenticate header: %s", h)
		}

		authReq, err := http.NewRequestWithContext(ctx, http.MethodGet, realm, nil)
		if err != nil {
			return false, nil
		}

		authReq.Header.Set("Authorization", "Basic "+basicAuth)
		authReq.Header.Set("Accept", "application/json")
		authReq.Header.Set("Content-Type", "application/json")

		params := url.Values{}
		params.Add("account", username)
		params.Add("service", authParams["service"])
		authReq.URL.RawQuery = params.Encode()

		authRes, err := client.Do(authReq)
		if err != nil {
			return false, err
		}
		defer func() {
			_, _ = io.Copy(io.Discard, authRes.Body)
			_ = authRes.Body.Close()
		}()

		switch authRes.StatusCode {
		case http.StatusOK:
			return true, nil
		case http.StatusUnauthorized, http.StatusForbidden:
			// Auth was rejected.
			return false, nil
		default:
			return false, fmt.Errorf("unexpected HTTP response status %d for '%s'", authRes.StatusCode, authReq.URL.String())
		}
	default:
		err = fmt.Errorf("unexpected HTTP response status %d for '%s'", res.StatusCode, req.URL.String())
		return false, err
	}
}

type dockerAuths struct {
	Auths map[string]dockerAuth `json:"auths"`
}

type dockerAuth struct {
	Auth     string `json:"auth"`
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

// parseBasicAuth handles cases where configs can have `username` and `password` but no `auth`,
// or vice-versa.
func parseBasicAuth(logger logr.Logger, auth dockerAuth) (string, string, string) {
	var (
		username string
		password string
	)

	if auth.Username != "" && auth.Password != "" {
		username = auth.Username
		password = auth.Password
	}

	if auth.Auth != "" {
		data, err := base64.StdEncoding.DecodeString(auth.Auth)
		if err != nil {
			goto end
		}

		parts := strings.SplitN(string(data), ":", 2)
		if len(parts) != 2 {
			logger.V(2).Info("Skipping invalid parts", "length", len(parts), "parts", parts)
			goto end
		}

		if (username != "" && parts[0] != username) || (password != "" && parts[1] != password) {
			logger.V(2).Info("WARNING: Creds have more than two usernames or passwords")
		}

		username = parts[0]
		password = parts[1]
	}

end:
	if username == "" && password == "" {
		return "", "", ""
	}

	basicAuth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	if auth.Auth != "" && basicAuth != auth.Auth {
		logger.Error(fmt.Errorf("base64-encoded auth does not match source"), "failed to parse auths JSON")
	}
	return username, password, basicAuth
}

// This is an ad-hoc implementation and not RFC compliant.
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/WWW-Authenticate
func parseAuthenticateHeader(headerValue string) (map[string]string, error) {
	authParams := make(map[string]string)

	parts := strings.Split(headerValue, " ")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid WWW-Authenticate header format")
	}
	authParams["scheme"] = parts[0]

	parts = strings.Split(parts[1], ",")
	for _, part := range parts {
		keyVal := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(keyVal) == 2 {
			key := strings.TrimSpace(keyVal[0])
			value := strings.Trim(strings.TrimSpace(keyVal[1]), `"`)
			authParams[key] = value
		}
	}

	return authParams, nil
}
