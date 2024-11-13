package airtableapikey

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client

	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	appPat      = regexp.MustCompile(`(app[\w-]{14})`) // could be part of url
	keyPat      = regexp.MustCompile(`\b(key[a-zA-Z0-9_-]{14})\b`)
	personalPat = regexp.MustCompile(`(\bpat[[:alnum:]]{14}\.[[:alnum:]]{64}\b)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"airtable"}
}

type response struct {
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// FromData will find and optionally verify AirtableApiKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	appMatches := make(map[string]struct{})
	for _, matches := range appPat.FindAllStringSubmatch(dataStr, -1) {
		appMatches[matches[1]] = struct{}{}
	}
	keyMatches := make(map[string]struct{})
	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		keyMatches[matches[1]] = struct{}{}
	}
	for _, matches := range personalPat.FindAllStringSubmatch(dataStr, -1) {
		keyMatches[matches[1]] = struct{}{}
	}

	for keyMatch := range keyMatches {
		var (
			r        *detectors.Result
			appMatch string
		)

		for a := range appMatches {
			appMatch = a

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := verifyMatch(ctx, client, appMatch, keyMatch)
				if isVerified {
					r = createResult(appMatch, keyMatch, isVerified, verificationErr)
					break
				}
			}
		}

		if r == nil {
			if len(appMatches) != 1 {
				appMatch = ""
			}
			r = createResult(appMatch, keyMatch, false, nil)
		}
		results = append(results, *r)
	}

	return results, nil
}

func createResult(app string, key string, verified bool, err error) *detectors.Result {
	r := &detectors.Result{
		DetectorType: detectorspb.DetectorType_AirtableApiKey,
		Raw:          []byte(key),
		Redacted:     app,
		Verified:     verified,
	}

	if app != "" {
		r.RawV2 = []byte(fmt.Sprintf(`%s:%s`, app, key))
	}

	if err != nil {
		r.SetVerificationError(err, key)
	}
	return r
}

func verifyMatch(ctx context.Context, client *http.Client, app string, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.airtable.com/v0/"+app+"/Projects", nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", key))
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	case http.StatusForbidden:
		var resp response
		if err = json.NewDecoder(res.Body).Decode(&resp); err != nil {
			return false, err
		}

		// check if the error is due to invalid permissions or model not found
		if resp.Error.Type == "INVALID_PERMISSIONS_OR_MODEL_NOT_FOUND" {
			// The key is verified as it works, but the user must enumerate the tables or permissions for the key.
			return true, nil
		}
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AirtableApiKey
}

func (s Scanner) Description() string {
	return "Airtable is a cloud collaboration service that offers database-like features. Airtable API keys can be used to access and modify data within Airtable bases."
}
