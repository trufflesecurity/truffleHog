package githubapp

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
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

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	appPat = regexp.MustCompile(detectors.PrefixRegex([]string{"github"}) + `\b([0-9]{6})\b`)

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"github"}) + `(-----BEGIN RSA PRIVATE KEY-----\s[A-Za-z0-9+\/\s]*\s-----END RSA PRIVATE KEY-----)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"github"}
}

// FromData will find and optionally verify GitHubApp secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	appMatches := appPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		resMatch := strings.TrimSpace(match[1])
		for _, appMatch := range appMatches {
			if len(appMatch) != 2 {
				continue
			}
			appResMatch := strings.TrimSpace(appMatch[1])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_GitHubApp,
				Raw:          []byte(resMatch),
			}
			s1.ExtraData = map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
			}

			if verify {
				signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(resMatch))
				if err != nil {
					continue
				}
				// issued at time
				iat := time.Now().Add(-60 * time.Second)
				exp := time.Now().Add(9 * 60 * time.Second)

				iss := appResMatch
				token := jwt.New(jwt.SigningMethodRS256)
				claims := token.Claims.(jwt.MapClaims)
				claims["iat"] = iat.Unix()
				claims["exp"] = exp.Unix()
				claims["iss"] = iss
				tokenString, err := token.SignedString(signKey)
				if err != nil {
					continue
				}
				// end get token

				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/app", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Accept", "application/vnd.github.v3+json")
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tokenString))
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
	return detectorspb.DetectorType_GitHubApp
}

func (s Scanner) Description() string {
	return "GitHub Apps allow you to automate and improve your workflow. GitHub App keys can be used to authenticate and interact with the GitHub API on behalf of the app."
}
