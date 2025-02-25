package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

func init() {
	ldap.DefaultTimeout = 5 * time.Second
}

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	uriPat = regexp.MustCompile(`\b(?i)ldaps?://[\S]+\b`)
	// ldap://127.0.0.1:389
	// ldap://127.0.0.1
	// ldap://mydomain.test
	// ldaps://[fe80:4049:92ff:fe44:4bd1]:5060
	// ldap://[fe80::4bd1]:5060
	// ldap://ds.example.com:389/dc=example,dc=com?givenName,sn,cn?sub?(uid=john.doe)
	usernamePat = regexp.MustCompile(detectors.PrefixRegex([]string{"user", "bind"}) + `["']([a-zA-Z=,]{4,150})["']`)
	passwordPat = regexp.MustCompile(detectors.PrefixRegex([]string{"pass"}) + `["']([\S]{4,48})["']`)

	// https://learn.microsoft.com/en-us/windows/win32/api/iads/nf-iads-iadsopendsobject-opendsobject?redirectedfrom=MSDN
	// I.E. Set ou = dso.OpenDSObject("LDAP://DC.business.com/OU=IT,DC=Business,DC=com", "Business\administrator", "Pa$$word01", 1)
	iadPat = regexp.MustCompile(`OpenDSObject\(\"(?i)(ldaps?://[\S]+)\", ?\"([\S]+)\", ?\"([\S]+)\",[ \d]+\)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ldaps://", "ldap://"}
}

// FromData will find and optionally verify Ldap secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Check for matches in the URI + username + password format
	uriMatches := map[*url.URL]struct{}{}
	for _, uri := range uriPat.FindAllString(dataStr, -1) {
		ldapURL, err := url.Parse(uri)
		if err != nil {
			continue
		}
		uriMatches[ldapURL] = struct{}{}
	}
	usernameMatches := map[string]struct{}{}
	for _, match := range usernamePat.FindAllStringSubmatch(dataStr, -1) {
		usernameMatches[match[1]] = struct{}{}
	}
	passwordMatches := map[string]struct{}{}
	for _, match := range passwordPat.FindAllStringSubmatch(dataStr, -1) {
		m := match[1]
		// Skip findings where the password only has "*" characters, this is a redacted password
		if strings.Trim(m, "*") == "" {
			continue
		}
		passwordMatches[m] = struct{}{}
	}

	for ldapURL := range uriMatches {
		for username := range usernameMatches {
			for password := range passwordMatches {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_LDAP,
					Raw:          []byte(strings.Join([]string{ldapURL.String(), username, password}, "\t")),
				}

				fmt.Printf("Searching: '%s'\n", string(s1.Raw))

				if verify {
					verificationErr := verifyLDAP(ldapURL, username, password)
					s1.Verified = verificationErr == nil
					if !isErrDeterminate(verificationErr) {
						s1.SetVerificationError(verificationErr, password)
					}
				}

				results = append(results, s1)
			}
		}
	}

	// Check for matches for the IAD library format
	iadMatches := map[string][2]string{}
	for _, match := range iadPat.FindAllStringSubmatch(dataStr, -1) {
		iadMatches[match[1]] = [2]string{match[2], match[3]}
	}
	for uri, values := range iadMatches {
		username := values[0]
		password := values[1]

		ldapURL, err := url.Parse(uri)
		if err != nil {
			continue
		}

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_LDAP,
			Raw:          []byte(strings.Join([]string{ldapURL.String(), username, password}, "\t")),
		}

		if verify {
			verificationError := verifyLDAP(ldapURL, username, password)

			s1.Verified = verificationError == nil
			if !isErrDeterminate(verificationError) {
				s1.SetVerificationError(verificationError, password)
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func isErrDeterminate(err error) bool {
	switch e := err.(type) {
	case *ldap.Error:
		switch e.Err.(type) {
		case *net.OpError:
			return false
		}
	}

	return true
}

func verifyLDAP(ldapURL *url.URL, username, password string) error {
	// Tests with non-TLS, TLS, and STARTTLS

	uri := ldapURL.String()
	var dialer = &net.Dialer{
		Timeout:   5 * time.Second,
		Deadline:  time.Now().Add(5 * time.Second),
		KeepAlive: -1,
	}

	ctx := logContext.WithValues(logContext.Background(), "url", uri, "username", username, "password", password)
	switch ldapURL.Scheme {
	case "ldap":
		ctx.Logger().Info("[ldap] Dialing")
		// Non-TLS dial
		l, err := ldap.DialURL(uri, ldap.DialWithDialer(dialer))
		if err != nil {
			return err
		}
		defer l.Close()
		// Non-TLS verify
		ctx.Logger().Info("[ldap] Dialing NON-TLS")
		if err = l.Bind(username, password); err == nil {
			return nil
		}

		// STARTTLS
		ctx.Logger().Info("[ldap] StartTLS")
		if err = l.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
			return err
		}
		// STARTTLS verify
		ctx.Logger().Info("[ldap] Bind")
		return l.Bind(username, password)
	case "ldaps":
		// TLS dial
		ctx.Logger().Info("[ldaps] Dialing")
		l, err := ldap.DialURL(uri, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}), ldap.DialWithDialer(dialer))
		if err != nil {
			return err
		}
		defer l.Close()
		// TLS verify
		ctx.Logger().Info("[ldaps] Bind")
		return l.Bind(username, password)
	default:
		return fmt.Errorf("unknown ldap scheme %q", ldapURL.Scheme)
	}

}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_LDAP
}

func (s Scanner) Description() string {
	return "LDAP (Lightweight Directory Access Protocol) is an open, vendor-neutral, industry standard application protocol for accessing and maintaining distributed directory information services over an Internet Protocol (IP) network."
}
