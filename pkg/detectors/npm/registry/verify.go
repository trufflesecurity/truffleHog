package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-logr/logr"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// VerifyToken attempts to verify the |token| based on the registry's type (if known).
//
// NOTE: some known registry types DO NOT SUPPORT VERIFICATION (yet?)
func VerifyToken(ctx context.Context, client *http.Client, registryInfo *Info, token string) (bool, map[string]string, error) {
	var (
		logCtx = context.WithValues(ctx, "registry", registryInfo.Uri, "token", token)

		whoamiRes *whoamiResponse
		searchRes *searchResponse
		allRes    *allResponse
		response  *http.Response
		err       error
	)
	if registryInfo.Scheme == UnknownScheme {
		// Sanity check — this should never happen.
		return false, nil, errors.New("registry scheme must be HTTP or HTTPS, not unknown")
	}

	switch registryInfo.Type {
	case other:
		// These support various endpoints.
		var errs []error
		whoamiRes, response, err = whoamiRequest(logCtx, client, registryInfo, token)
		if whoamiRes != nil {
			return true, map[string]string{"username": whoamiRes.Username}, nil
		}
		if err != nil {
			if common.ErrIsNoSuchHost(err) {
				return false, nil, err
			}
			errs = append(errs, err)
		}

		searchRes, response, err = searchRequest(logCtx, client, registryInfo, token)
		if searchRes != nil {
			return true, nil, nil
		}
		if err != nil {
			errs = append(errs, err)
		}

		allRes, response, err = allRequest(logCtx, client, registryInfo, token)
		if allRes != nil {
			return true, nil, nil
		}
		if err != nil {
			errs = append(errs, err)
		}

		return false, nil, errors.Join(errs...)
	case npm:
		whoamiRes, response, err = whoamiRequest(logCtx, client, registryInfo, token)
		if whoamiRes != nil {
			return true, map[string]string{"username": whoamiRes.Username}, nil
		}
		return false, nil, err
	case artifactoryCloud, artifactoryHosted:
		// Returns {"username":"anonymous"} if no auth is provided.
		// Using /AllEndpoint or /SearchEndpoint seems to return a vague "One or more query value parameters are null" error. Not sure why.
		whoamiRes, response, err = whoamiRequest(logCtx, client, registryInfo, token)
		if whoamiRes != nil && whoamiRes.Username != "anonymous" {
			return true, map[string]string{"username": whoamiRes.Username}, nil
		}
		return false, nil, err
	case nexusRepo2:
		// Returns 401 if auth is invalid, doesn't support WhoamiEndpoint or SearchEndpoint.
		allRes, response, err = allRequest(logCtx, client, registryInfo, token)
		if allRes != nil {
			return true, nil, nil
		}
		return false, nil, err
	case nexusRepo3:
		// Returns {"username":"anonymous"} or 401 for WhoamiEndpoint. Supports both AllEndpoint and SearchEndpoint.
		whoamiRes, response, err = whoamiRequest(logCtx, client, registryInfo, token)
		if whoamiRes != nil && whoamiRes.Username != "anonymous" {
			return true, map[string]string{"username": whoamiRes.Username}, nil
		}
		return false, nil, err
	case gitlab:
		// GitLab does not support any meta endpoints, only direct package lookups.
		// https://docs.gitlab.com/ee/user/packages/npm_registry/#package-forwarding-to-npmjscom
		// TODO:
		return false, nil, fmt.Errorf("GitLab verification is not supported")
	case githubCloud:
		// Returns 403 if auth is invalid.
		whoamiRes, response, err = whoamiRequest(logCtx, client, registryInfo, token)
		if whoamiRes != nil {
			return true, map[string]string{"username": whoamiRes.Username}, nil
		}
		if response != nil && response.StatusCode == http.StatusForbidden {
			if err != nil && strings.Contains(err.Error(), "unexpected response status") {
				err = nil
			}
		}
		return false, nil, err
	case azure:
		// Doesn't support SearchEndpoint.
		// https://github.com/MicrosoftDocs/azure-devops-docs/issues/10455
		whoamiRes, response, err = whoamiRequest(logCtx, client, registryInfo, token)
		if whoamiRes != nil {
			return true, map[string]string{"username": whoamiRes.Username}, nil
		}
		return false, nil, err
	case jetbrains:
		// Does not support AllEndpoint.
		// Returns 401 if auth is invalid.
		whoamiRes, response, err = whoamiRequest(logCtx, client, registryInfo, token)
		if whoamiRes != nil && whoamiRes.Username != "internal" {
			return true, map[string]string{"username": whoamiRes.Username}, nil
		}
		return false, nil, err

	case googleArtifactRegistry:
		// Does not support WhoamiEndpoint, AllEndpoint, or SearchEndpoint. (https://stackoverflow.com/q/76470861)
		// Returns 404 for valid token, 403 for invalid token.
		// TODO
		return false, nil, fmt.Errorf("Google Artifact Registry verification is not supported")
	case gemfury:
		// Returns 401 if auth is invalid.
		whoamiRes, response, err = whoamiRequest(logCtx, client, registryInfo, token)
		if whoamiRes == nil {
			return false, nil, err
		}
		return true, map[string]string{"username": whoamiRes.Username}, nil
	case awsCodeArtifact:
		// TODO
		return false, nil, fmt.Errorf("AWS Code Artifact verification is not supported")
	default:
		return false, nil, fmt.Errorf("unrecognized registry type: %s", registryInfo.Type)
	}
}

func closeResponseBody(response *http.Response) {
	if response == nil {
		return
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
}

func logger(ctx context.Context) logr.Logger {
	return ctx.Logger().WithName("npm")
}

// whoamiRequest attempts to call the `/-/whoami` registry endpoint.
// See: https://github.com/npm/documentation/blob/f030a50fcf72bf3b8445c2ff63745644bbdb81c1/content/cli/v7/commands/npm-whoami.md?plain=1#L30
func whoamiRequest(
	ctx context.Context,
	client *http.Client,
	registryInfo *Info,
	authValue string,
) (*whoamiResponse, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s%s/-/whoami", registryInfo.Scheme.String(), registryInfo.Uri), nil)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authValue))
	res, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer closeResponseBody(res)

	logger(ctx).V(3).Info("Got whoami response", "status_code", res.StatusCode)
	switch res.StatusCode {
	case http.StatusOK:
		var whoamiRes whoamiResponse
		if err := json.NewDecoder(res.Body).Decode(&whoamiRes); err != nil {
			return nil, res, err
		}

		// It is possible for the response to be `{"username": null}`, `{"username":""}`, etc.
		// While a valid token _can_ return an empty username, the registry is likely returning 200 for invalid auth.
		if whoamiRes.Username == "" {
			return nil, res, nil
		}
		return &whoamiRes, res, nil
	case http.StatusUnauthorized:
		return nil, res, nil
	default:
		body, _ := io.ReadAll(res.Body)
		return nil, res, fmt.Errorf("unexpected response status %d for %s, body = %q", res.StatusCode, req.URL, string(body))
	}
}

type whoamiResponse struct {
	Username string `json:"username"`
}

// searchRequest attempts to call the `/-/v1/search` registry endpoint.
// See: https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md#get-v1search
func searchRequest(
	ctx context.Context,
	client *http.Client,
	registryInfo *Info,
	authValue string,
) (*searchResponse, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s%s/-/v1/search", registryInfo.Scheme.String(), registryInfo.Uri), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to construct search request: %s", err)
	}

	query := url.Values{}
	query.Add("text", "test")
	query.Add("size", "1")
	req.URL.RawQuery = query.Encode()
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authValue))

	res, err := client.Do(req)
	if err != nil {
		// A |tls.RecordHeaderError| likely means that the server is using HTTP, not HTTPS.
		// TODO: Is it possible to handle the reverse case?
		// TODO: Handle this at the DoVerificationLevel
		// var tlsErr tls.RecordHeaderError
		// if errors.As(err, &tlsErr) && registryScheme == registry.HttpsScheme {
		// 	return searchRequest(ctx, client, registry.HttpScheme, registryUri, authType, authValue)
		// }
		return nil, res, fmt.Errorf("search request failed: %w", err)
	}
	defer closeResponseBody(res)

	logger(ctx).V(3).Info("Got search response", "status_code", res.StatusCode)
	switch res.StatusCode {
	case http.StatusOK:
		var searchRes searchResponse
		if err := json.NewDecoder(res.Body).Decode(&searchRes); err != nil {
			return nil, res, err
		}
		if (searchRes == searchResponse{}) {
			return nil, res, fmt.Errorf("failed to decode search response JSON")
		}
		return &searchRes, res, nil
	case http.StatusUnauthorized:
		return nil, res, nil
	default:
		body, _ := io.ReadAll(res.Body)
		return nil, res, fmt.Errorf("unexpected response status %d for %s, body = %q", res.StatusCode, req.URL, string(body))
	}
}

type searchResponse struct {
	Ok    bool   `json:"ok"`
	Total int    `json:"total"`
	Time  string `json:"time"`
}

// allRequest attempts to call the `/-/all` registry endpoint.
// While the endpoint is deprecated, some older registries don't support the newer whoami/search endpoints.
// See: https://blog.npmjs.org/post/157615772423/deprecating-the-all-registry-endpoint.html
func allRequest(
	ctx context.Context,
	client *http.Client,
	registryInfo *Info,
	authValue string,
) (*allResponse, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s%s/-/all", registryInfo.Scheme.String(), registryInfo.Uri), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to construct all request: %s", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authValue))
	res, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer closeResponseBody(res)

	logger(ctx).V(3).Info("Got all response", "status_code", res.StatusCode)
	switch res.StatusCode {
	case http.StatusOK:
		var allRes allResponse
		if err := json.NewDecoder(res.Body).Decode(&allRes); err != nil {
			return nil, res, err
		}

		if allRes.Updated == 0 {
			return nil, res, fmt.Errorf("failed to decode all response JSON")
		}
		return &allRes, res, nil
	case http.StatusUnauthorized:
		return nil, res, nil
	default:
		body, _ := io.ReadAll(res.Body)
		return nil, res, fmt.Errorf("unexpected response status %d for %s, body=%q", res.StatusCode, req.URL, string(body))
	}
}

type allResponse struct {
	Updated int `json:"_updated"`
}
