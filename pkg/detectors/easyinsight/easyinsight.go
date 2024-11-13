package easyinsight

import (
	"context"
	"fmt"
	"io"
	"net/http"

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"easyinsight", "easy-insight", "key"}) + `\b([0-9a-zA-Z]{20})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"easyinsight", "easy-insight", "id"}) + `\b([a-zA-Z0-9]{20})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"easyinsight", "easy-insight"}
}

// FromData will find and optionally verify EasyInsight secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var keyMatches, idMatches = make(map[string]struct{}), make(map[string]struct{})

	// get unique key and id matches
	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		keyMatches[matches[1]] = struct{}{}
	}

	for _, matches := range idPat.FindAllStringSubmatch(dataStr, -1) {
		idMatches[matches[1]] = struct{}{}
	}

	for keyMatch := range keyMatches {
		for idMatch := range idMatches {
			//as key and id regex are same, the strings captured by both regex will be same.
			//avoid processing when key is same as id. This will allow detector to process only different combinations
			if keyMatch == idMatch {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_EasyInsight,
				Raw:          []byte(keyMatch),
				RawV2:        []byte(keyMatch + idMatch),
			}

			if verify {
				verified, verificationErr := verifyEasyInsight(ctx, idMatch, keyMatch)
				s1.Verified = verified
				if verificationErr != nil {
					s1.SetVerificationError(verificationErr)
				}
			}

			results = append(results, s1)
			// if key id combination is verified, skip other idMatches for that key
			if s1.Verified {
				break
			}
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_EasyInsight
}

func (s Scanner) Description() string {
	return "EasyInsight is a business intelligence tool that provides data visualization and reporting. EasyInsight API keys can be used to access and manage data within the platform."
}

func verifyEasyInsight(ctx context.Context, id, key string) (bool, error) {
	// docs: https://www.easy-insight.com/api/users.html
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.easy-insight.com/app/api/users.json", nil)
	if err != nil {
		return false, err
	}

	// add required headers to the request
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	// set basic auth for the request
	req.SetBasicAuth(id, key)

	res, reqErr := client.Do(req)
	if reqErr != nil {
		return false, reqErr
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	// id, key verified
	case http.StatusOK:
		return true, nil
	// id, key unverified
	case http.StatusUnauthorized:
		return false, nil
	// something invalid
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}
