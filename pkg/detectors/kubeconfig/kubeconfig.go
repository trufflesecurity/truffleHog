package kubeconfig

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	*detectors.CustomMultiPartCredentialProvider
}

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ interface {
		detectors.Detector
		detectors.MultiPartCredentialProvider
	} = (*Scanner)(nil)
	defaultClient = common.SaneHttpClient()

	invalidHosts = simple.NewCache[struct{}]()
)

func New() Scanner {
	s := Scanner{}
	s.CustomMultiPartCredentialProvider = detectors.NewCustomMultiPartCredentialProvider(4096) // ????
	return s
}

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"current-context"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_KubeConfig
}

func (s Scanner) Description() string {
	return "KubeConfig credentials can allow unauthorized access to a Kubernetes cluster."
}

// FromData will find and optionally verify KubeConfig secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	logCtx := logContext.AddLogger(ctx)
	logger := logCtx.Logger().WithName("kubeconfig")
	dataStr := string(data)

	// A crude method to differentiate JSON and YAML configs.
	var (
		clusters []cluster
		errs     []error
	)
	if jsonpat.MatchString(dataStr) {
		clusters, errs = parseJson(dataStr)
	} else {
		clusters, errs = parseYaml(dataStr)
	}

	if len(errs) > 0 {
		for _, pErr := range errs {
			// Fatal errors
			if errors.Is(pErr, noClustersObjectError) ||
				errors.Is(pErr, noClusterEntriesError) ||
				errors.Is(pErr, noContextsObjectError) ||
				errors.Is(pErr, noContextsError) ||
				errors.Is(pErr, noUsersObjectError) ||
				errors.Is(pErr, noUsersError) {
				return
			}

			logger.Error(pErr, "Failed to parse config")
		}
	}
	if len(clusters) == 0 {
		return
	}

	for _, cluster := range clusters {
		r := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(cluster.Auth.GetValue()),
			RawV2:        []byte(fmt.Sprintf(`{"server":"%s","user":"%s","auth":"%s"}`, cluster.Server, cluster.GetUser(), cluster.Auth.GetValue())),
			ExtraData: map[string]string{
				"Server": cluster.Server,
				"User":   cluster.User,
				"Type":   cluster.Auth.Type.String(),
			},
		}

		if verify {
			if invalidHosts.Exists(cluster.Server) {
				logger.Info("Skipping non-resolving server", "server", cluster.Server)
				continue
			}

			client := s.client
			if client == nil {
				client = defaultClient
			}
			patchTransport(client)

			verified, extraData, verificationErr := verifyCluster(logCtx, client, cluster)
			r.Verified = verified
			for k, v := range extraData {
				r.ExtraData[k] = v
			}

			if verificationErr != nil {
				if strings.Contains(verificationErr.Error(), "no such host") {
					invalidHosts.Set(cluster.Server, struct{}{})
				}
				r.SetVerificationError(verificationErr)
			}
		}

		results = append(results, r)
	}

	return
}

func verifyCluster(ctx logContext.Context, client *http.Client, cluster cluster) (bool, map[string]string, error) {
	logger := ctx.Logger().WithName("kubeconfig")

	namespacesUrl, err := url.JoinPath(cluster.Server, "/api/v1/namespaces")
	if err != nil {
		return false, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, namespacesUrl+"?limit=10", nil)
	if err != nil {
		return false, nil, nil
	}

	// https://github.com/kubernetes/kubernetes/blob/e0e6c9633d5f9a388cbf9c7757c789afaec11c34/cmd/kubeadm/app/phases/kubeconfig/kubeconfig.go#L171
	// https://github.com/kubernetes/kubernetes/blob/e0e6c9633d5f9a388cbf9c7757c789afaec11c34/staging/src/k8s.io/client-go/plugin/pkg/client/auth/exec/exec.go#L291
	switch cluster.Auth.Type {
	case clientKeyAuth:
		// Requires mutual TLS auth.
		// Need to investigate this.
	case passwordAuth:
		req.SetBasicAuth(cluster.User, cluster.Auth.Password)
	case tokenAuth:
		req.Header.Set("Authorization", "Bearer "+cluster.Auth.Token)
	default:
		// This should never happen.
		logger.Info("Skipping authentication for unknown auth type", "type", cluster.Auth.Type.String())
	}
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return false, nil, err
	}

	switch res.StatusCode {
	case http.StatusOK:
		var nsRes namespaceListResponse
		if err := json.Unmarshal(body, &nsRes); err != nil {
			return false, nil, err
		}

		var extraData map[string]string
		if len(nsRes.Items) > 0 {
			var sb strings.Builder
			for i, ns := range nsRes.Items {
				if i > 0 {
					sb.WriteString(",")
				}
				sb.WriteString(ns.Metadata.Name)
			}

			if nsRes.Metadata.Continue != "" {
				sb.WriteString(" (+ more)")
			}

			extraData = map[string]string{
				"Namespaces": sb.String(),
			}
		}
		return true, extraData, nil
	case http.StatusUnauthorized:
		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	case http.StatusForbidden:
		// The auth was valid but the user lacks permission.
		return true, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response: status=%d, body=%q", res.StatusCode, string(body))
	}
}

// patchTransport disables TLS certificate validation.
// This is necessary because many k8s clusters use self-signed certificates.
func patchTransport(c *http.Client) {
	transport, ok := c.Transport.(*http.Transport)
	if !ok || transport == nil {
		transport = &http.Transport{}
	}

	// Allow self-signed certificates.
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	c.Transport = transport
}

// https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#namespacelist-v1-core
type namespaceListResponse struct {
	Items    []item `json:"items"`
	Metadata listMetadata
}

type listMetadata struct {
	Continue string `json:"continue"`
}

type item struct {
	Metadata itemMetadata `json:"metadata"`
}

type itemMetadata struct {
	Name string `json:"name"`
}
