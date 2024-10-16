package hasura

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	domainPat = regexp.MustCompile(`\b([a-zA-Z0-9-]+\.hasura\.app)\b`)
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"hasura"}) + `\b([a-zA-Z0-9]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"hasura"}
}

// FromData will find and optionally verify Hasura secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	domainMatches := domainPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range keyMatches {
		if len(match) != 2 {
			continue
		}
		key := strings.TrimSpace(match[1])

		for _, domainMatch := range domainMatches {
			if len(domainMatch) != 2 {
				continue
			}

			domainRes := strings.TrimSpace(domainMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Hasura,
				Raw:          []byte(key),
				RawV2:        []byte(fmt.Sprintf("%s:%s", domainRes, key)),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				data := []byte(`{"query":"query { __schema { types { name } } }"}`)
				req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("https://%s/v1/graphql", domainRes), strings.NewReader(string(data)))
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				req.Header.Add("x-hasura-admin-secret", key)
				res, err := client.Do(req)
				if err != nil {
					s1.SetVerificationError(err, key)
					results = append(results, s1)
					continue
				}
				defer res.Body.Close()

				body, err := ioutil.ReadAll(res.Body)
				if err != nil {
					s1.SetVerificationError(err, key)
					results = append(results, s1)
					continue
				}

				var response struct {
					Errors []interface{} `json:"errors"`
				}

				err = json.Unmarshal(body, &response)
				if err != nil {
					s1.SetVerificationError(err, key)
					results = append(results, s1)
					continue
				}

				if res.StatusCode >= 200 && res.StatusCode < 300 && len(response.Errors) == 0 {
					s1.Verified = true
				} else {
					if len(response.Errors) > 0 {
						err = fmt.Errorf("GraphQL query returned errors")
					} else {
						err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
					}
					s1.SetVerificationError(err, key)
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Hasura
}

func (s Scanner) Description() string {
	return "Hasura is an open source engine that provides instant GraphQL APIs over PostgreSQL. Hasura admin secrets can be used to access and manage Hasura projects."
}
