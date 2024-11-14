package ftp

import (
	"context"
	"errors"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/jlaffaye/ftp"
	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const (
	// https://datatracker.ietf.org/doc/html/rfc959
	ftpNotLoggedIn = 530

	defaultVerificationTimeout = 5 * time.Second
)

type Scanner struct {
	// Verification timeout. Defaults to 5 seconds if unset.
	verificationTimeout time.Duration
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

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

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_FTP,
			Raw:          []byte(rawURL.String()),
			Redacted:     redact,
		}

		if verify {
			timeout := s.verificationTimeout
			if timeout == 0 {
				timeout = defaultVerificationTimeout
			}
			verificationErr := verifyFTP(timeout, parsedURL)
			s1.Verified = verificationErr == nil
			if !isErrDeterminate(verificationErr) {
				s1.SetVerificationError(verificationErr, password)
			}
		}

		if !s1.Verified {
			// Skip unverified findings where the password starts with a `$` - it's almost certainly a variable.
			if strings.HasPrefix(password, "$") {
				continue
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

var ftpFalsePositives = map[detectors.FalsePositive]struct{}{
	detectors.FalsePositive("@ftp.freebsd.org"): {},
}

func (s Scanner) IsFalsePositive(result detectors.Result) (bool, string) {
	return detectors.IsKnownFalsePositive(string(result.Raw), ftpFalsePositives, false)
}

func isErrDeterminate(e error) bool {
	ftpErr := &textproto.Error{}
	return errors.As(e, &ftpErr) && ftpErr.Code == ftpNotLoggedIn
}

func verifyFTP(timeout time.Duration, u *url.URL) error {
	host := u.Host
	if !strings.Contains(host, ":") {
		host = host + ":21"
	}

	c, err := ftp.Dial(host, ftp.DialWithTimeout(timeout))
	if err != nil {
		return err
	}

	password, _ := u.User.Password()
	return c.Login(u.User.Username(), password)
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_FTP
}

func (s Scanner) Description() string {
	return "FTP is a protocol for reading and writing files. An FTP password can be used to read and sometimes write files."
}
