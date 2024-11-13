package deepai

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"deepai"}) + `\b([a-z0-9-]{36})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"deepai"}
}

// FromData will find and optionally verify DeepAI secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_DeepAI,
			Raw:          []byte(resMatch),
		}

		if verify {
			body := &bytes.Buffer{}
			writer := multipart.NewWriter(body)
			fw, err := writer.CreateFormField("text")
			if err != nil {
				continue
			}
			_, err = io.Copy(fw, strings.NewReader("test"))
			if err != nil {
				continue
			}
			writer.Close()
			req, err := http.NewRequestWithContext(ctx, "POST", "https://api.deepai.org/api/text-tagging", bytes.NewReader(body.Bytes()))
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", writer.FormDataContentType())
			req.Header.Add("api-key", resMatch)
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_DeepAI
}

func (s Scanner) Description() string {
	return "DeepAI is an AI service provider offering various machine learning APIs. DeepAI API keys can be used to access and utilize these services."
}
