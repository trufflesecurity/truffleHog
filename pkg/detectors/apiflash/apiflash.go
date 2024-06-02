package apiflash

import (
	"context"
	"fmt"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"apiflash"}) + `\b([a-z0-9]{32})\b`)

	urlToCapture = "http://google.com" // a fix constant url to capture to verify the access key
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"apiflash"}
}

// FromData will find and optionally verify Apiflash secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueAPIKeys := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAPIKeys[strings.TrimSpace(match[1])] = struct{}{}
	}

	for key := range uniqueAPIKeys {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Apiflash,
			Raw:          []byte(key),
		}

		if verify {
			if s.client == nil {
				s.client = detectors.GetHttpClientWithNoLocalAddresses()
			}
			isVerified, verificationErr := verifyAPIFlash(ctx, s.client, key)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, key)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Apiflash
}

func (s Scanner) Description() string {
	return "Apiflash is a screenshot API service. Apiflash keys can be used to access and utilize the screenshot API service."
}

func verifyAPIFlash(ctx context.Context, client *http.Client, accessKey string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.apiflash.com/v1/urltoimage?url=%s&access_key=%s&wait_until=page_loaded", urlToCapture, accessKey), http.NoBody)
	if err != nil {
		return false, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, nil
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
