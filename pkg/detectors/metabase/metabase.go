package metabase

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

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
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"metabase"}) + `\b([a-zA-Z0-9-]{36})\b`)

	baseURL = regexp.MustCompile(detectors.PrefixRegex([]string{"metabase"}) + `\b(https?:\/\/[-a-zA-Z0-9@:%._\+~#=]{7,256})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"metabase"}
}

// FromData will find and optionally verify Metabase secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	urlMatches := baseURL.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, urlMatch := range urlMatches {
			resURLMatch := strings.TrimSpace(urlMatch[1])

			u, err := detectors.ParseURLAndStripPathAndParams(resURLMatch)
			if err != nil {
				// if the URL is invalid just move onto the next one
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Metabase,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resURLMatch),
			}

			if verify {
				if s.client == nil {
					s.client = detectors.GetHttpClientWithLocalAddresses()
				}

				u.Path = "/api/user/current"
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
				if err != nil {
					continue
				}
				req.Header.Add("X-Metabase-Session", resMatch)
				res, err := s.client.Do(req)
				if err == nil {
					defer res.Body.Close()
					body, err := io.ReadAll(res.Body)
					if err != nil {
						continue
					}
					if res.StatusCode == http.StatusOK && json.Valid(body) {
						s1.Verified = true
					}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Metabase
}

func (s Scanner) Description() string {
	return "Metabase is an open-source business intelligence tool. Metabase session tokens can be used to access and interact with the Metabase API."
}
