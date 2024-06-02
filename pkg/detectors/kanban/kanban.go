package kanban

import (
	"context"
	"fmt"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"kanban"}) + `\b([0-9A-Z]{12})\b`)
	urlPat = regexp.MustCompile(`\b([0-9a-z]{1,}\.kanbantool\.com)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"kanban"}
}

// FromData will find and optionally verify Kanban secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	urlMatches := urlPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])
		for _, urlMatch := range urlMatches {
			resURL := strings.TrimSpace(urlMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Kanban,
				Raw:          []byte(resMatch),
			}

			if verify {
				if s.client == nil {
					s.client = detectors.GetHttpClientWithNoLocalAddresses()
				}

				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/api/v3/users/current.json", resURL), nil)
				if err != nil {
					continue
				}
				req.Header.Add("Accept", "application/vnd.kanban+json; version=3")
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
				res, err := s.client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
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
	return detectorspb.DetectorType_Kanban
}

func (s Scanner) Description() string {
	return "KanbanTool is a project management software that helps visualize and optimize workflow. Kanban API keys can be used to access and modify project data."
}
