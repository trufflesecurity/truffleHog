package aha

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
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"aha"}) + `\b([0-9a-f]{64})\b`)
	URLPat = regexp.MustCompile(`\b([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])\.aha\.io)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"aha.io"}
}

// FromData will find and optionally verify Aha secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	URLmatches := URLPat.FindAllStringSubmatch(dataStr, -1)

	resURLMatch := "aha.io"
	for _, URLmatch := range URLmatches {
		resURLMatch = strings.TrimSpace(URLmatch[1])
	}

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Aha,
			Raw:          []byte(resMatch),
		}

		if verify {
			if s.client == nil {
				s.client = detectors.GetHttpClientWithNoLocalAddresses()
			}
			isVerified, verificationErr := verifyAha(ctx, s.client, resMatch, resURLMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyAha(ctx context.Context, client *http.Client, resMatch, resURLMatch string) (bool, error) {
	url := fmt.Sprintf("https://%s/api/v1/me", resURLMatch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Accept", "application/vnd.aha+json; version=3")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	// https://www.aha.io/api
	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusNotFound, http.StatusForbidden:
		// 403 is a known case where an account is inactive bc of a trial ending or payment issue
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Aha
}

func (s Scanner) Description() string {
	return "Aha is a product management software suite. Aha API keys can be used to access and modify product data and workflows."
}
