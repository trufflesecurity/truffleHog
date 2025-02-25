package v1

import (
	"context"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azure_entra"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azure_entra/serviceprincipal"
	v2 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azure_entra/serviceprincipal/v2"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ interface {
	detectors.Detector
	detectors.Versioner
} = (*Scanner)(nil)

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Azure
}

func (s Scanner) Description() string {
	return serviceprincipal.Description
}

func (s Scanner) Version() int {
	return 1
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"azure", "az", "entra", "msal", "login.microsoftonline.com", ".onmicrosoft.com"}
}

var (
	defaultClient = common.SaneHttpClient()
	// TODO: Azure storage access keys and investigate other types of creds.
	// https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow#second-case-access-token-request-with-a-certificate
	// https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow#third-case-access-token-request-with-a-federated-credential
	// clientSecretPat = regexp.MustCompile(`(?i)(?:secret|password| -p[ =]).{0,80}?([\w~@[\]:.?*/+=-]{31,34}`)
	// TODO: Tighten this regex and replace it with above.
	secretPat = regexp.MustCompile(`(?i)(?:secret|password| -p[ =]).{0,80}[^A-Za-z0-9!#$%&()*+,\-./:;<>?@[\\\]^_{|}~]([A-Za-z0-9!#$%&()*+,\-./:;<=>?@[\\\]^_{|}~]{31,34})(?:\s|\z|[^A-Za-z0-9!#$%&()*+,\-./:;<=>?@[\\\]^_{|}~])`)

	invalidMatchPat  = regexp.MustCompile(`^passwordCredentials":`)
	invalidSecretPat = regexp.MustCompile(`^[a-zA-Z]+$`)
)

// FromData will find and optionally verify Azure secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	clientSecrets := findSecretMatches(dataStr)
	if len(clientSecrets) == 0 {
		return
	}
	clientIds := azure_entra.FindClientIdMatches(dataStr)
	if len(clientIds) == 0 {
		return
	}
	tenantIds := azure_entra.FindTenantIdMatches(dataStr)

	client := s.client
	if client == nil {
		client = defaultClient
	}
	// The handling logic is identical for both versions.
	results = append(results, v2.ProcessData(ctx, clientSecrets, clientIds, tenantIds, verify, client)...)
	return results, nil
}

func findSecretMatches(data string) map[string]struct{} {
	uniqueMatches := make(map[string]struct{})
	for _, match := range secretPat.FindAllStringSubmatch(data, -1) {
		m := match[1]
		if v2.SecretPat.MatchString(m) {
			// Ignore secrets that are handled by the V2 detector.
			continue
		} else if detectors.StringShannonEntropy(m) < 3 {
			// Ignore low-entropy results.
			continue
		} else if invalidSecretPat.MatchString(m) || invalidMatchPat.MatchString(match[0]) {
			// Ignore patterns that are known to be false.
			continue
		}
		uniqueMatches[m] = struct{}{}
	}
	return uniqueMatches
}
