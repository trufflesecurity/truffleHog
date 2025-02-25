package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"

	regexp "github.com/wasilibs/go-re2"
	"golang.org/x/oauth2/google"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ interface {
	detectors.Detector
	detectors.CustomFalsePositiveChecker
	detectors.MaxSecretSizeProvider
	detectors.StartOffsetProvider
} = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(`\{[^{]+auth_provider_x509_cert_url[^}]+\}`)
)

type gcpKey struct {
	Type                    string `json:"type"`
	ProjectID               string `json:"project_id"`
	PrivateKeyID            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientID                string `json:"client_id"`
	AuthURI                 string `json:"auth_uri"`
	TokenURI                string `json:"token_uri"`
	AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url"`
	ClientX509CertURL       string `json:"client_x509_cert_url"`
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"provider_x509"}
}

const maxGCPKeySize = 2048

// MaxSecretSize returns the maximum size of a secret that this detector can find.
func (Scanner) MaxSecretSize() int64 { return maxGCPKeySize }

const startOffset = 4096

// StartOffset returns the start offset for the secret this detector finds.
func (Scanner) StartOffset() int64 { return startOffset }

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_GCP
}

func (s Scanner) Description() string {
	return "GCP (Google Cloud Platform) is a suite of cloud computing services that runs on the same infrastructure that Google uses internally for its end-user products. GCP keys can be used to access and manage these services."
}

// FromData will find and optionally verify GCP secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllString(dataStr, -1) {
		uniqueMatches[match] = struct{}{}
	}

	for match := range uniqueMatches {
		key := cleanInput(match)

		creds := gcpKey{}
		if err := json.NewDecoder(strings.NewReader(key)).Decode(&creds); err != nil {
			continue
		}

		// for Slack mangling (mailto scheme and hyperlinks)
		if strings.Contains(creds.ClientEmail, `<mailto:`) {
			creds.ClientEmail = strings.Split(strings.Split(creds.ClientEmail, `<mailto:`)[1], `|`)[0]
		}
		creds.AuthProviderX509CertURL = trimCarets(creds.AuthProviderX509CertURL)
		creds.AuthURI = trimCarets(creds.AuthURI)
		creds.ClientX509CertURL = trimCarets(creds.ClientX509CertURL)
		creds.TokenURI = trimCarets(creds.TokenURI)

		// Not sure why this might happen, but we've observed this with a verified cred
		raw := []byte(creds.ClientEmail)
		if len(raw) == 0 {
			raw = []byte(key)
		}
		// This is an unprivileged service account used in Kubernetes' tests. It is intentionally public.
		// https://github.com/kubernetes/kubernetes/blob/10a06602223eab17e02e197d1da591727c756d32/test/e2e_node/runtime_conformance_test.go#L50
		if bytes.Equal(raw, []byte("image-pulling@authenticated-image-pulling.iam.gserviceaccount.com")) {
			continue
		}

		credBytes, _ := json.Marshal(creds)

		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_GCP,
			Raw:          raw,
			RawV2:        credBytes,
			Redacted:     creds.ClientEmail,
			ExtraData: map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/gcp/",
				"project":        creds.ProjectID,
			},
			AnalysisInfo: map[string]string{
				"principal": creds.ClientEmail,
			},
		}

		if creds.Type != "" {
			result.AnalysisInfo["type"] = creds.Type
		}

		if verify {
			isVerified, verificationErr := verifyMatch(ctx, credBytes)
			result.Verified = isVerified
			result.SetVerificationError(verificationErr, match)
		}

		results = append(results, result)
	}

	return
}

func verifyMatch(ctx context.Context, credBytes []byte) (bool, error) {
	credentials, err := google.CredentialsFromJSON(ctx, credBytes, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return false, err
	}

	if _, err = credentials.TokenSource.Token(); err != nil {
		if strings.Contains(err.Error(), "invalid_grant") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s Scanner) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

// region Helper methods
func cleanInput(input string) string {
	input = strings.ReplaceAll(input, `,\\n`, `\n`)
	input = strings.ReplaceAll(input, `\"\\n`, `\n`)
	input = strings.ReplaceAll(input, `\\"`, `"`)

	// If the JSON is encoded, it needs to be unquoted for `json.Unmarshal` to succeed.
	// https://github.com/trufflesecurity/trufflehog/issues/2864
	if strings.Contains(input, `\"auth_provider_x509_cert_url\"`) {
		unquoted, err := strconv.Unquote(`"` + input + `"`)
		if err == nil {
			return unquoted
		}
	}

	return input
}

func trimCarets(s string) string {
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")
	return s
}

//endregion
