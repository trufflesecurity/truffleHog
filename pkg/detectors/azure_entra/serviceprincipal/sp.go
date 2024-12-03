package serviceprincipal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var (
	Description                = "Azure is a cloud service offering a wide range of services including compute, analytics, storage, and networking. Azure credentials can be used to access and manage these services."
	ErrConditionalAccessPolicy = errors.New("access blocked by Conditional Access policies (AADSTS53003)")
	ErrSecretInvalid           = errors.New("invalid client secret provided")
	ErrSecretExpired           = errors.New("the provided secret is expired")
	ErrTenantNotFound          = errors.New("tenant not found")
	ErrClientNotFoundInTenant  = errors.New("application was not found in tenant")
)

type TokenOkResponse struct {
	AccessToken string `json:"access_token"`
}

type TokenErrResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// VerifyCredentials attempts to get a token using the provided client credentials.
// See: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow#get-a-token
func VerifyCredentials(ctx context.Context, client *http.Client, tenantId string, clientId string, clientSecret string) (bool, map[string]string, error) {
	data := url.Values{}
	data.Set("client_id", clientId)
	data.Set("scope", "https://graph.microsoft.com/.default")
	data.Set("client_secret", clientSecret)
	data.Set("grant_type", "client_credentials")

	tokenUrl := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantId)
	encodedData := data.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenUrl, strings.NewReader(encodedData))
	if err != nil {
		return false, nil, nil
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(encodedData)))

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	// Credentials are valid.
	if res.StatusCode == http.StatusOK {
		var okResp TokenOkResponse
		if err := json.NewDecoder(res.Body).Decode(&okResp); err != nil {
			return false, nil, err
		}

		extraData := map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/azure/",
			"tenant":         tenantId,
			"client":         clientId,
		}

		// Add claims from the access token.
		if token, _ := jwt.Parse(okResp.AccessToken, nil); token != nil {
			claims := token.Claims.(jwt.MapClaims)

			if app := claims["app_displayname"]; app != nil {
				extraData["application"] = fmt.Sprint(app)
			}
		}
		return true, extraData, nil
	}

	// Credentials *probably* aren't valid.
	var errResp TokenErrResponse
	if err := json.NewDecoder(res.Body).Decode(&errResp); err != nil {
		return false, nil, err
	}
	
	switch res.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized:
		// Error codes can be looked up by removing the `AADSTS` prefix.
		// https://login.microsoftonline.com/error?code=9002313
		// TODO: Handle AADSTS900382 (https://github.com/Azure/azure-sdk-for-js/issues/30557)
		d := errResp.Description
		switch {
		case strings.HasPrefix(d, "AADSTS53003:"):
			return false, nil, ErrConditionalAccessPolicy
		case strings.HasPrefix(d, "AADSTS700016:"):
			// https://login.microsoftonline.com/error?code=700016
			return false, nil, ErrClientNotFoundInTenant
		case strings.HasPrefix(d, "AADSTS7000215:"):
			// https://login.microsoftonline.com/error?code=7000215
			return false, nil, ErrSecretInvalid
		case strings.HasPrefix(d, "AADSTS7000222:"):
			// The secret has expired.
			// https://login.microsoftonline.com/error?code=7000222
			return false, nil, ErrSecretExpired
		case strings.HasPrefix(d, "AADSTS90002:"):
			// https://login.microsoftonline.com/error?code=90002
			return false, nil, ErrTenantNotFound
		default:
			return false, nil, fmt.Errorf("unexpected error '%s': %s", errResp.Error, errResp.Description)
		}
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}
