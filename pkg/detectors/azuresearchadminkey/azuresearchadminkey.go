package azuresearchadminkey

import (
	"context"
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

	servicePat = regexp.MustCompile(`\b([a-z0-9][a-z0-9-]{5,58}[a-z0-9])\.search\.windows\.net`)
	keyPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"azure", "windows.net"}) + `\b([a-zA-Z0-9]{52})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"search.windows.net"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureSearchAdminKey
}

func (s Scanner) Description() string {
	return "Azure Search is a search-as-a-service solution that allows developers to incorporate search capabilities into their applications. Azure Search Admin Keys can be used to manage and query search services."
}

// FromData will find and optionally verify AzureSearchAdminKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Deduplicate results.
	serviceMatches := make(map[string]struct{})
	for _, matches := range servicePat.FindAllStringSubmatch(dataStr, -1) {
		serviceMatches[matches[1]] = struct{}{}
	}
	keyMatches := make(map[string]struct{})
	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		k := matches[1]
		if detectors.StringShannonEntropy(k) < 4 {
			continue
		}
		keyMatches[k] = struct{}{}
	}

	for key := range keyMatches {
		for service := range serviceMatches {
			r := detectors.Result{
				DetectorType: detectorspb.DetectorType_AzureSearchAdminKey,
				Raw:          []byte(key),
				RawV2:        []byte(`{"service":"` + service + `","key":"` + key + `"}`),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := verifyMatch(ctx, client, service, key)
				r.Verified = isVerified
				r.SetVerificationError(verificationErr, key)
			}

			results = append(results, r)
			if r.Verified {
				break
			}
		}
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, service string, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+service+".search.windows.net/servicestats?api-version=2023-10-01-Preview", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("api-key", key)

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
	case http.StatusUnauthorized, http.StatusForbidden:
		// The secret is determinately not verified.
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}
