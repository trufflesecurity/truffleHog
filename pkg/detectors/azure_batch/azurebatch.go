package azure_batch

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

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
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	urlPat    = regexp.MustCompile(`https://(.{1,50})\.(.{1,50})\.batch\.azure\.com`)
	secretPat = regexp.MustCompile(`[A-Za-z0-9+/=]{88}`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{".batch.azure.com"}
}

// FromData will find and optionally verify Azurebatch secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	urlMatches := urlPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, urlMatch := range urlMatches {

		for _, secretMatch := range secretMatches {

			endpoint := urlMatch[0]
			accountName := urlMatch[1]
			accountKey := secretMatch[0]

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AzureBatch,
				Raw:          []byte(endpoint),
				RawV2:        []byte(endpoint + accountKey),
				Redacted:     endpoint,
			}

			if verify {
				if s.client == nil {
					s.client = detectors.GetHttpClientWithNoLocalAddresses()
				}
				url := fmt.Sprintf("%s/applications?api-version=2020-09-01.12.0", endpoint)
				date := time.Now().UTC().Format(http.TimeFormat)
				stringToSign := fmt.Sprintf(
					"GET\n\n\n\n\napplication/json\n%s\n\n\n\n\n\n%s\napi-version:%s",
					date,
					strings.ToLower(fmt.Sprintf("/%s/applications", accountName)),
					"2020-09-01.12.0",
				)
				key, _ := base64.StdEncoding.DecodeString(accountKey)
				h := hmac.New(sha256.New, key)
				h.Write([]byte(stringToSign))
				signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
				req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", fmt.Sprintf("SharedKey %s:%s", accountName, signature))
				req.Header.Set("Date", date)
				resp, err := s.client.Do(req)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					s1.Verified = true
				}

			}

			results = append(results, s1)
			if s1.Verified {
				break
			}
		}
	}

	return results, nil
}

func (s Scanner) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureBatch
}

func (s Scanner) Description() string {
	return "Azure Batch is a cloud service that provides large-scale parallel and high-performance computing (HPC) applications efficiently in the cloud. Azure Batch account keys can be used to manage and control access to these resources."
}
