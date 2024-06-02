package uri

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	allowKnownTestSites bool
	client              *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ interface {
	detectors.Detector
	detectors.CustomFalsePositiveChecker
} = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(`\bhttps?:\/\/[\w!#$%&()*+,\-./;<=>?@[\\\]^_{|}~]{0,50}:([\w!#$%&()*+,\-./:;<=>?[\\\]^_{|}~]{3,50})@[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})?(?::\d{1,5})?[\w/]+\b`)

	hostNotFoundCache = simple.NewCache[struct{}]()
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"http://", "https://"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_URI
}

func (s Scanner) Description() string {
	return "This detector identifies URLs with embedded credentials, which can be used to access web resources without explicit user interaction."
}

// FromData will find and optionally verify URI secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	logger := logContext.AddLogger(ctx).Logger().WithName("uri")
	dataStr := string(data)

	uriMatches := make(map[string]string)
	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uriMatch := matches[0]
		if !s.allowKnownTestSites {
			if strings.Contains(uriMatch, "httpbin.org") {
				continue
			}
			if strings.Contains(uriMatch, "httpwatch.com") {
				continue
			}
		}

		password := matches[1]
		// Skip findings where the password only has "*" characters, this is a redacted password
		// Also include the url encoded "*" characters: "%2A"
		if strings.Trim(password, "*") == "" || strings.Trim(password, "%2A") == "" {
			continue
		}

		uriMatches[uriMatch] = password
	}

	for uri, password := range uriMatches {
		parsedURL, err := url.Parse(uri)
		if err != nil {
			// URL is invalid.
			continue
		}
		// URL does not contain a password.
		if _, ok := parsedURL.User.Password(); !ok {
			continue
		}

		// Safe, I think? (https://github.com/golang/go/issues/38351)
		rawUrl := *parsedURL
		rawUrlWithPath := rawUrl.String()
		// Removing the path causes possible deduplication issues if some paths have basic auth and some do not.
		rawUrl.Path = ""
		rawUrlWithoutPath := rawUrl.String()

		r := detectors.Result{
			DetectorType: detectorspb.DetectorType_URI,
			Raw:          []byte(rawUrlWithoutPath),
			RawV2:        []byte(rawUrlWithPath),
			Redacted:     detectors.RedactURL(*parsedURL),
		}

		if verify {
			hostname := parsedURL.Hostname()
			if hostNotFoundCache.Exists(hostname) {
				logger.V(3).Info("Skipping uri: no such host", "host", hostname)
				continue
			}

			// TODO: make local addr opt-out
			if s.client == nil {
				s.client = detectors.GetHttpClientWithNoLocalAddresses()
			}
			isVerified, vErr := verifyURL(ctx, s.client, parsedURL)
			r.Verified = isVerified
			if vErr != nil {
				var dnsErr *net.DNSError
				if errors.As(vErr, &dnsErr) && dnsErr.IsNotFound {
					hostNotFoundCache.Set(hostname, struct{}{})
				}
				r.SetVerificationError(vErr, password)
			}
		}

		if !r.Verified {
			// Skip unverified findings where the password starts with a `$` - it's almost certainly a variable.
			if strings.HasPrefix(password, "$") {
				continue
			}
		}

		results = append(results, r)
	}

	return results, nil
}

func (s Scanner) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

func verifyURL(ctx context.Context, client *http.Client, u *url.URL) (bool, error) {
	// defuse most SSRF payloads
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""

	credentialedURL := u.String()

	u.User = nil
	nonCredentialedURL := u.String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, credentialedURL, nil)
	if err != nil {
		return false, err
	}

	credentialedRes, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, credentialedRes.Body)
		_ = credentialedRes.Body.Close()
	}()

	// If the credentialed URL returns a non 2XX code, we can assume it's a false positive.
	if credentialedRes.StatusCode < 200 || credentialedRes.StatusCode > 299 {
		return false, nil
	}

	time.Sleep(time.Millisecond * 10)

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, nonCredentialedURL, nil)
	if err != nil {
		return false, err
	}

	nonCredentialedRes, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, nonCredentialedRes.Body)
		_ = nonCredentialedRes.Body.Close()
	}()

	// If the non-credentialed URL returns a non 400-428 code and basic auth header, we can assume it's verified now.
	if nonCredentialedRes.StatusCode >= 400 && nonCredentialedRes.StatusCode < 429 {
		if nonCredentialedRes.Header.Get("WWW-Authenticate") != "" {
			return true, nil
		}
	}

	return false, nil
}
