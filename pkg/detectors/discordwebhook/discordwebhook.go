package discordwebhook

import (
	"context"
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
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`(https:\/\/discord\.com\/api\/webhooks\/[0-9]{18}\/[0-9a-zA-Z-]{68})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string { return []string{"https://discord.com/api/webhooks/"} }

// FromData will find and optionally verify DiscordWebhook secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_DiscordWebhook,
			Raw:          []byte(resMatch),
		}

		if verify {
			if s.client == nil {
				s.client = detectors.GetHttpClientWithNoLocalAddresses()
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, resMatch, nil)
			if err != nil {
				continue
			}
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_DiscordWebhook
}

func (s Scanner) Description() string {
	return "Discord webhooks are used to send messages to a Discord channel. They can be used to automate messages and send data updates."
}
