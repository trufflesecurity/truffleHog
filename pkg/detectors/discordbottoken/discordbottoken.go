package discordbottoken

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"discord"}) + `\b([0-9]{17})\b`)
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"discord"}) + `\b([A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"discord"}
}

// FromData will find and optionally verify DiscordBotToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatch := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, idmatch := range idMatch {
			if len(match) != 2 {
				continue
			}
			resId := strings.TrimSpace(idmatch[1])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_DiscordBotToken,
				Redacted:     resId,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resId),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://discord.com/api/v8/users/"+resId, nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Bot %s", resMatch))
				res, err := client.Do(req)
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
	return detectorspb.DetectorType_DiscordBotToken
}

func (s Scanner) Description() string {
	return "Discord bot tokens are used to authenticate and control Discord bots. These tokens can be used to interact with the Discord API to perform various bot-related operations."
}
