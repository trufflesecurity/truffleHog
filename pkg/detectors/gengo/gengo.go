package gengo

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	// Removed bounds since there are some cases where the start and end of the token is a special character
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"gengo"}) + `([ ]{0,1}[0-9a-zA-Z\[\]\-\(\)\{\}|_^@$=~]{64}[ \r\n]{1})`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"gengo"}) + `([ ]{0,1}[0-9a-zA-Z\[\]\-\(\)\{\}|_^@$=~]{64}[ \r\n]{1})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"gengo"}
}

// FromData will find and optionally verify Gengo secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, secretMatch := range secretMatches {
			if len(secretMatch) != 2 {
				continue
			}
			resSecretMatch := strings.TrimSpace(secretMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Gengo,
				Raw:          []byte(resSecretMatch),
				RawV2:        []byte(resMatch + resSecretMatch),
			}

			if verify {

				timestamp := strconv.FormatInt(time.Now().Unix(), 10)
				signature := getGengoSignature(timestamp, resSecretMatch)

				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.gengo.com/v2/account/me?ts=%s&api_key=%s&api_sig=%s", timestamp, resMatch, signature), nil)
				if err != nil {
					continue
				}
				req.Header.Add("Accept", "application/json")
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					body, errBody := io.ReadAll(res.Body)

					if errBody == nil {
						var response Response
						if err := json.Unmarshal(body, &response); err != nil {
							continue
						}

						if res.StatusCode >= 200 && res.StatusCode < 300 && response.OpStat == "ok" {
							s1.Verified = true
						}
					}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

type Response struct {
	OpStat string `json:"opstat"`
}

func getGengoSignature(timeStamp string, secret string) string {

	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(timeStamp))
	macsum := mac.Sum(nil)
	return hex.EncodeToString(macsum)
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Gengo
}

func (s Scanner) Description() string {
	return "Gengo is a platform for professional human translation services. Gengo API keys can be used to access and manage translation projects and resources."
}
