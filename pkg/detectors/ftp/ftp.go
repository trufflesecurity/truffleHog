package ftp

import (
	"context"
	"errors"
	"net/textproto"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jlaffaye/ftp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

// https://datatracker.ietf.org/doc/html/rfc959
const ftpNotLoggedIn = 530

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(`\bftp://[\S]{3,50}:([\S]{3,50})@[-.%\w\/:]+\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ftp://"}
}

// FromData will find and optionally verify URI secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		urlMatch := match[0]
		password := match[1]

		// Skip findings where the password only has "*" characters, this is a redacted password
		if strings.Trim(password, "*") == "" {
			continue
		}

		parsedURL, err := url.Parse(urlMatch)
		if err != nil {
			continue
		}
		if _, ok := parsedURL.User.Password(); !ok {
			continue
		}
		if parsedURL.User.Username() == "anonymous" {
			continue
		}

		rawURL, _ := url.Parse(urlMatch)
		rawURL.Path = ""
		redact := strings.TrimSpace(strings.Replace(rawURL.String(), password, "********", -1))

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_FTP,
			Raw:          []byte(rawURL.String()),
			Redacted:     redact,
		}

		if verify {
			verificationErr := verifyFTP(ctx, parsedURL)
			s.Verified = verificationErr == nil
			if !isErrDeterminate(verificationErr) {
				s.VerificationError = verificationErr
			}
		}

		if !s.Verified {
			// Skip unverified findings where the password starts with a `$` - it's almost certainly a variable.
			if strings.HasPrefix(password, "$") {
				continue
			}
		}

		if detectors.IsKnownFalsePositive(string(s.Raw), []detectors.FalsePositive{"@ftp.freebsd.org"}, false) {
			continue
		}

		results = append(results, s)
	}

	return results, nil
}

func isErrDeterminate(e error) bool {
	ftpErr := &textproto.Error{}
	return errors.As(e, &ftpErr)
}

func verifyFTP(ctx context.Context, u *url.URL) error {
	host := u.Host
	if !strings.Contains(host, ":") {
		host = host + ":21"
	}

	c, err := ftp.Dial(host, ftp.DialWithTimeout(5*time.Second))
	if err != nil {
		return err
	}

	password, _ := u.User.Password()
	return c.Login(u.User.Username(), password)
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_FTP
}
