package v2

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azure_entra"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azure_entra/serviceprincipal"
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
	return 2
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"q~"}
}

var (
	defaultClient = common.SaneHttpClient()

	SecretPat = regexp.MustCompile(`(?:[^a-zA-Z0-9_~.-]|\A)([a-zA-Z0-9_~.-]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:[^a-zA-Z0-9_~.-]|\z)`)
)

// FromData will find and optionally verify Azure secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	clientSecrets := findSecretMatches(dataStr)
	if len(clientSecrets) == 0 {
		return results, nil
	}
	clientIds := azure_entra.FindClientIdMatches(dataStr)
	tenantIds := azure_entra.FindTenantIdMatches(dataStr)

	client := s.client
	if client == nil {
		client = defaultClient
	}

	results = append(results, ProcessData(ctx, clientSecrets, clientIds, tenantIds, verify, client)...)
	return results, nil
}

func ProcessData(ctx context.Context, clientSecrets, clientIds, tenantIds map[string]struct{}, verify bool, client *http.Client) (results []detectors.Result) {
	logCtx := logContext.AddLogger(ctx)
	invalidClientsForTenant := make(map[string]map[string]struct{})

SecretLoop:
	for clientSecret := range clientSecrets {
		var (
			r        *detectors.Result
			clientId string
			tenantId string
		)

	ClientLoop:
		for cId := range clientIds {
			clientId = cId
			for tId := range tenantIds {
				tenantId = tId

				// Skip known invalid tenants.
				invalidClients := invalidClientsForTenant[tenantId]
				if invalidClients == nil {
					invalidClients = map[string]struct{}{}
					invalidClientsForTenant[tenantId] = invalidClients
				}
				if _, ok := invalidClients[clientId]; ok {
					continue
				}

				if verify {
					fmt.Printf("Testing: [tenant=%s, client=%s, secret=%s]\n", tenantId, clientId, clientSecret)
					if !azure_entra.TenantExists(logCtx, client, tenantId) {
						// Tenant doesn't exist
						delete(tenantIds, tenantId)
						continue
					}
					// Tenant exists, ensure this isn't attempted as a clientId.
					delete(clientIds, tenantId)

					isVerified, extraData, verificationErr := serviceprincipal.VerifyCredentials(ctx, client, tenantId, clientId, clientSecret)
					// Handle errors.
					if verificationErr != nil {
						switch {
						case errors.Is(verificationErr, serviceprincipal.ErrConditionalAccessPolicy):
							// Do nothing.
						case errors.Is(verificationErr, serviceprincipal.ErrSecretInvalid):
							continue ClientLoop
						case errors.Is(verificationErr, serviceprincipal.ErrSecretExpired):
							continue SecretLoop
						case errors.Is(verificationErr, serviceprincipal.ErrTenantNotFound):
							// Tenant doesn't exist. This shouldn't happen with the check above.
							delete(tenantIds, tenantId)
							continue
						case errors.Is(verificationErr, serviceprincipal.ErrClientNotFoundInTenant):
							// Tenant is valid but the ClientID doesn't exist.
							invalidClients[clientId] = struct{}{}
							continue
						}
					}

					// The result is verified or there's only one associated client and tenant.
					if isVerified || (len(clientIds) == 1 && len(tenantIds) == 1) {
						r = createResult(tenantId, clientId, clientSecret, isVerified, extraData, verificationErr)
						break ClientLoop
					}
				}
			}
		}

		if r == nil {
			// Only include the clientId and tenantId if we're confident which one it is.
			if len(clientIds) != 1 {
				clientId = ""
			}
			if len(tenantIds) != 1 {
				tenantId = ""
			}
			r = createResult(tenantId, clientId, clientSecret, false, nil, nil)
		}

		results = append(results, *r)
	}
	return results
}

func createResult(tenantId string, clientId string, clientSecret string, verified bool, extraData map[string]string, err error) *detectors.Result {
	r := &detectors.Result{
		DetectorType: detectorspb.DetectorType_Azure,
		Raw:          []byte(clientSecret),
		ExtraData:    extraData,
		Verified:     verified,
		Redacted:     clientSecret[:5] + "...",
	}
	r.SetVerificationError(err, clientSecret)

	// Tenant ID is required for verification, but it may not always be present.
	// e.g., ACR or Azure SQL use client id+secret without tenant.
	if clientId != "" && tenantId != "" {
		var sb strings.Builder
		sb.WriteString(`{`)
		sb.WriteString(`"clientSecret":"` + clientSecret + `"`)
		sb.WriteString(`,"clientId":"` + clientId + `"`)
		sb.WriteString(`,"tenantId":"` + tenantId + `"`)
		sb.WriteString(`}`)
		r.RawV2 = []byte(sb.String())
	}

	return r
}

func findSecretMatches(data string) map[string]struct{} {
	uniqueMatches := make(map[string]struct{})
	for _, match := range SecretPat.FindAllStringSubmatch(data, -1) {
		m := match[1]
		if detectors.StringShannonEntropy(m) < 3 {
			continue
		}
		uniqueMatches[m] = struct{}{}
	}
	return uniqueMatches
}
