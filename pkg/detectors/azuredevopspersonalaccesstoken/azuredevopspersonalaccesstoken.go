package azure_devops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
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

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureDevopsPersonalAccessToken
}

func (s Scanner) Description() string {
	return "Azure DevOps is a suite of development tools provided by Microsoft. Personal Access Tokens (PATs) are used to authenticate and authorize access to Azure DevOps services and resources."
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"dev.azure.com", "az devops"}
}

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"azure", "az", "token", "pat"}) + `\b([a-z0-9]{52}|[a-zA-Z0-9]{84})\b`)
	orgPat = regexp.MustCompile(`dev\.azure\.com/([0-9a-zA-Z][0-9a-zA-Z-]{5,48}[0-9a-zA-Z])\b`)

	invalidOrgCache = simple.NewCache[struct{}]()
)

// FromData will find and optionally verify AzureDevopsPersonalAccessToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Deduplicate results.
	keyMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		m := match[1]
		if detectors.StringShannonEntropy(m) < 3 {
			continue
		}
		keyMatches[m] = struct{}{}
	}
	orgMatches := make(map[string]struct{})
	for _, match := range orgPat.FindAllStringSubmatch(dataStr, -1) {
		m := match[1]
		if invalidOrgCache.Exists(m) {
			continue
		}
		orgMatches[m] = struct{}{}
	}

	for key := range keyMatches {
		for org := range orgMatches {
			r := detectors.Result{
				DetectorType: detectorspb.DetectorType_AzureDevopsPersonalAccessToken,
				Raw:          []byte(key),
				RawV2:        []byte(fmt.Sprintf(`{"organization":"%s","token":"%s"}`, org, key)),
			}

			if verify {
				if s.client == nil {
					s.client = common.SaneHttpClient()
				}

				isVerified, extraData, verificationErr := verifyMatch(ctx, s.client, org, key)
				r.Verified = isVerified
				r.ExtraData = extraData
				if verificationErr != nil {
					if errors.Is(verificationErr, errInvalidOrg) {
						delete(orgMatches, org)
						invalidOrgCache.Set(org, struct{}{})
						continue
					}
					r.SetVerificationError(verificationErr)
				}
			}

			results = append(results, r)
		}
	}

	return results, nil
}

var errInvalidOrg = errors.New("invalid organization")

func verifyMatch(ctx context.Context, client *http.Client, org string, key string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://dev.azure.com/"+org+"/_apis/projects", nil)
	if err != nil {
		return false, nil, err
	}

	req.SetBasicAuth("", key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		// {"count":1,"value":[{"id":"...","name":"Test","url":"https://dev.azure.com/...","state":"wellFormed","revision":11,"visibility":"private","lastUpdateTime":"2024-12-16T02:23:58.86Z"}]}
		var projectsRes listProjectsResponse
		if json.NewDecoder(res.Body).Decode(&projectsRes) != nil {
			return false, nil, err
		}

		// Condense a list of organizations + roles.
		var (
			extraData map[string]string
			projects  = make([]string, 0, len(projectsRes.Value))
		)
		for _, p := range projectsRes.Value {
			projects = append(projects, p.Name)
		}
		if len(projects) > 0 {
			extraData = map[string]string{
				"projects": strings.Join(projects, ","),
			}
		}
		return true, extraData, nil
	case http.StatusUnauthorized:
		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	case http.StatusNotFound:
		// Org doesn't exist.
		return false, nil, errInvalidOrg
	default:
		body, _ := io.ReadAll(res.Body)
		return false, nil, fmt.Errorf("unexpected HTTP response: status=%d, body=%q", res.StatusCode, string(body))
	}
}

type listProjectsResponse struct {
	Count int               `json:"count"`
	Value []projectResponse `json:"value"`
}

type projectResponse struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}
