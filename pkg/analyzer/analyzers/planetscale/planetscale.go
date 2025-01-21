//go:generate generate_permissions permissions.yaml permissions.go planetscale

package planetscale

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypePlanetScale }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	id, ok := credInfo["id"]
	if !ok {
		return nil, errors.New("missing id in credInfo")
	}
	key, ok := credInfo["key"]
	if !ok {
		return nil, errors.New("missing key in credInfo")
	}
	info, err := AnalyzePermissions(a.Cfg, id, key)
	if err != nil {
		return nil, err
	}
	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}
	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypePlanetScale,
		Metadata:     nil,
		Bindings:     make([]analyzers.Binding, len(info.Permissions)),
	}

	resource := analyzers.Resource{
		Name:               info.Organization,
		FullyQualifiedName: info.Organization,
		Type:               "Organization",
		Metadata: map[string]any{
			"expires": "never",
		},
	}

	for idx, permission := range info.Permissions {
		result.Bindings[idx] = analyzers.Binding{
			Resource: resource,
			Permission: analyzers.Permission{
				Value: permission,
			},
		}
	}

	return &result
}

//go:embed scopes.json
var scopesConfig []byte

type HttpStatusTest struct {
	Endpoint        string      `json:"endpoint"`
	Method          string      `json:"method"`
	Payload         interface{} `json:"payload"`
	ValidStatuses   []int       `json:"valid_status_code"`
	InvalidStatuses []int       `json:"invalid_status_code"`
}

func StatusContains(status int, vals []int) bool {
	for _, v := range vals {
		if status == v {
			return true
		}
	}
	return false
}

func (h *HttpStatusTest) RunTest(cfg *config.Config, headers map[string]string, organization string) (bool, error) {
	// If body data, marshal to JSON
	var data io.Reader
	if h.Payload != nil {
		jsonData, err := json.Marshal(h.Payload)
		if err != nil {
			return false, err
		}
		data = bytes.NewBuffer(jsonData)
	}

	// Create new HTTP request
	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest(h.Method, fmt.Sprintf(h.Endpoint, organization), data)
	if err != nil {
		return false, err
	}

	// Add custom headers if provided
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Execute HTTP Request
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// Check response status code
	switch {
	case StatusContains(resp.StatusCode, h.ValidStatuses):
		return true, nil
	case StatusContains(resp.StatusCode, h.InvalidStatuses):
		return false, nil
	default:
		return false, errors.New("error checking response status code")
	}
}

type Scopes struct {
	OrganizationScopes     []Scope `json:"organization_scopes"`
	OAuthApplicationScopes []Scope `json:"oauth_application_scopes"`
	DatabaseScopes         []Scope `json:"database_scopes"`
}

type Scope struct {
	Name     string         `json:"name"`
	HttpTest HttpStatusTest `json:"test"`
}

func readInScopes() (*Scopes, error) {
	var scopes Scopes
	if err := json.Unmarshal(scopesConfig, &scopes); err != nil {
		return nil, err
	}

	return &scopes, nil
}

func checkPermissions(cfg *config.Config, id, key, organization string) ([]string, error) {
	scopes, err := readInScopes()
	if err != nil {
		return nil, fmt.Errorf("reading in scopes: %w", err)
	}

	permissions := make([]string, 0)
	for _, scope := range scopes.OrganizationScopes {
		status, err := scope.HttpTest.RunTest(cfg, map[string]string{"Authorization": fmt.Sprintf("%s:%s", id, key)}, organization)
		if err != nil {
			return nil, fmt.Errorf("running test: %w", err)
		}
		if status {
			permissions = append(permissions, scope.Name)
		}
	}

	return permissions, nil
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

type SecretInfo struct {
	Organization string
	Permissions  []string
}

func AnalyzeAndPrintPermissions(cfg *config.Config, id, key string) {
	info, err := AnalyzePermissions(cfg, id, key)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
		return
	}

	color.Green("[!] Valid PlanetScale credentials\n\n")
	color.Green("[i] Organization: %s", info.Organization)
	printPermissions(info.Permissions)
	color.Yellow("\n[i] Expires: Never")

}

func AnalyzePermissions(cfg *config.Config, id, key string) (*SecretInfo, error) {
	var info = &SecretInfo{}

	organization, err := getOrganization(cfg, id, key)
	if err != nil {
		return nil, fmt.Errorf("getting organization: %w", err)
	}

	permissions, err := checkPermissions(cfg, id, key, organization)
	if err != nil {
		return nil, err
	}

	if len(permissions) == 0 {
		return nil, fmt.Errorf("invalid PlanetScale credentials")
	}

	info.Permissions = permissions
	info.Organization = organization

	return info, nil
}

type organizationJSON struct {
	Data []struct {
		Name string `json:"name"`
	} `json:"data"`
}

func getOrganization(cfg *config.Config, id, key string) (string, error) {
	url := "https://api.planetscale.com/v1/organizations"

	client := analyzers.NewAnalyzeClient(cfg)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("%s:%s", id, key))

	// Execute HTTP Request
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("invalid credentials")
	}

	// Decode response body
	var organizationJSON organizationJSON
	err = json.NewDecoder(resp.Body).Decode(&organizationJSON)
	if err != nil {
		return "", err
	}

	return organizationJSON.Data[0].Name, nil

}

func printPermissions(permissions []string) {
	color.Yellow("[i] Permissions:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Permission"})
	for _, permission := range permissions {
		t.AppendRow(table.Row{color.GreenString(permission)})
	}
	t.Render()
}
