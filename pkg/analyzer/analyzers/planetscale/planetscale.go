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
	"slices"
	"strings"

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
	key, ok := credInfo["token"]
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
		Bindings:     make([]analyzers.Binding, len(info.OrgPermissions)),
	}

	resource := analyzers.Resource{
		Name:               info.OrgName,
		FullyQualifiedName: info.OrgName,
		Type:               "Organization",
	}

	for idx, permission := range info.OrgPermissions {
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

func (h *HttpStatusTest) RunTest(cfg *config.Config, headers map[string]string, args ...any) (bool, error) {
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
	req, err := http.NewRequest(h.Method, fmt.Sprintf(h.Endpoint, args...), data)
	if err != nil {
		return false, err
	}

	// Add custom headers if provided
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	req.Header.Add("Content-Type", "application/json")

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
	OrganizationScopes     []Scope       `json:"organization_scopes"`
	OAuthApplicationScopes []Scope       `json:"oauth_application_scopes"`
	DatabaseScopes         []Scope       `json:"database_scopes"`
	BranchScopes           []BranchScope `json:"branch_scopes"`
}

type Scope struct {
	Name     string         `json:"name"`
	HttpTest HttpStatusTest `json:"test"`
}

type BranchScope struct {
	Scope
	Production bool `json:"production"`
}

func readInScopes() (*Scopes, error) {
	var scopes Scopes
	if err := json.Unmarshal(scopesConfig, &scopes); err != nil {
		return nil, err
	}

	return &scopes, nil
}

func checkPermissions(cfg *config.Config, scopes []Scope, id, key string, args ...any) ([]string, error) {

	permissions := make([]string, 0)
	for _, scope := range scopes {
		status, err := scope.HttpTest.RunTest(cfg, map[string]string{"Authorization": fmt.Sprintf("%s:%s", id, key)}, args...)
		if err != nil {
			return nil, fmt.Errorf("running test: %w", err)
		}
		if status {
			permissions = append(permissions, scope.Name)
		}
	}

	return permissions, nil
}

func checkBranchPermissions(cfg *config.Config, scopes []BranchScope, id, key, organization, db, branch string, production bool) ([]string, error) {
	permissions := make([]string, 0)
	for _, scope := range scopes {
		if production != scope.Production {
			continue
		}
		status, err := scope.HttpTest.RunTest(cfg, map[string]string{"Authorization": fmt.Sprintf("%s:%s", id, key)}, organization, db, branch)
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
	OrgName             string
	OrgPermissions      []string
	DatabasePermissions map[Database][]string
}

func AnalyzeAndPrintPermissions(cfg *config.Config, id, token string) {
	info, err := AnalyzePermissions(cfg, id, token)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
		return
	}

	color.Green("[!] Valid PlanetScale credentials\n\n")
	color.Green("[i] Organization: %s\n\n", info.OrgName)
	printOrganizationPermissions(info.OrgPermissions)

	if len(info.DatabasePermissions) > 0 {
		printDatabasePermissions(info.DatabasePermissions)
	}
}

func AnalyzePermissions(cfg *config.Config, id, token string) (*SecretInfo, error) {
	var info = &SecretInfo{}

	orgName, err := getOrganizationName(cfg, id, token)
	if err != nil {
		return nil, err
	}
	info.OrgName = orgName

	scopes, err := readInScopes()
	if err != nil {
		return nil, fmt.Errorf("reading in scopes: %w", err)
	}

	organizationPermissions, err := checkPermissions(cfg, scopes.OrganizationScopes, id, token, orgName)
	if err != nil {
		return nil, err
	}
	info.OrgPermissions = organizationPermissions

	// if len(permissions) == 0 {
	// 	return nil, fmt.Errorf("invalid credentials")
	// }

	readOAuthApplicationPermission, _ := ReadOauthApplications.ToString()
	if slices.Contains(organizationPermissions, readOAuthApplicationPermission) {
		oauthApplicationId, err := getOAuthApplicationId(cfg, id, token, orgName)
		if err != nil {
			return nil, err
		}

		oauthPermissions, err := checkPermissions(cfg, scopes.OAuthApplicationScopes, id, token, orgName, oauthApplicationId)
		if err != nil {
			return nil, err
		}
		info.OrgPermissions = append(info.OrgPermissions, oauthPermissions...)
	}

	databases, err := getDatabases(cfg, id, token, orgName)
	if err != nil {
		return nil, err
	}

	info.DatabasePermissions = make(map[Database][]string)
	for _, database := range databases {
		dbPermissions, err := checkPermissions(cfg, scopes.DatabaseScopes, id, token, orgName, database.Name)
		if err != nil {
			return nil, err
		}
		info.DatabasePermissions[database] = dbPermissions

		readBranchPermission, _ := ReadBranch.ToString()
		if slices.Contains(dbPermissions, readBranchPermission) {
			branches, err := getDbBranches(cfg, id, token, orgName, database.Name)
			if err != nil {
				return nil, err
			}

			// get permissions for prod and non prod branches
			prodDone, nonProdDone := false, false
			for _, branch := range branches {
				if branch.Production {
					prodDone = true
				} else {
					nonProdDone = true
				}
				branchPermissions, err := checkBranchPermissions(cfg, scopes.BranchScopes, id, token, orgName, database.Name, branch.Name, branch.Production)
				if err != nil {
					return nil, err
				}
				info.DatabasePermissions[database] = append(info.DatabasePermissions[database], branchPermissions...)

				if prodDone && nonProdDone {
					break
				}
			}
		}
	}

	return info, nil
}

type organizationJSON struct {
	Data []struct {
		Name string `json:"name"`
	} `json:"data"`
}

func getOrganizationName(cfg *config.Config, id, key string) (string, error) {
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

	// Check response status code
	switch resp.StatusCode {
	case http.StatusOK:
		// Decode response body
		var organizationJSON organizationJSON
		err = json.NewDecoder(resp.Body).Decode(&organizationJSON)
		if err != nil {
			return "", err
		}

		return organizationJSON.Data[0].Name, nil
	case http.StatusUnauthorized:
		return "", fmt.Errorf("invalid credentials")
	default:
		return "", fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
}

type oauthApplicationJSON struct {
	Data []struct {
		Id string `json:"id"`
	}
}

func getOAuthApplicationId(cfg *config.Config, id, key, organization string) (string, error) {
	url := "https://api.planetscale.com/v1/organizations/%s/oauth-applications"

	client := analyzers.NewAnalyzeClient(cfg)

	req, err := http.NewRequest("GET", fmt.Sprintf(url, organization), nil)
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

	// Check response status code
	switch resp.StatusCode {
	case http.StatusOK:
		// Decode response body
		var oauthApplicationJSON oauthApplicationJSON
		err = json.NewDecoder(resp.Body).Decode(&oauthApplicationJSON)
		if err != nil {
			return "", err
		}

		if len(oauthApplicationJSON.Data) > 0 {
			return oauthApplicationJSON.Data[0].Id, nil
		}
		return "", nil // no oauth application found
	case http.StatusUnauthorized:
		return "", fmt.Errorf("invalid credentials")
	default:
		return "", fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
}

type Database struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}
type databasesJSON struct {
	Data        []Database `json:"data"`
	NextPageUrl string     `json:"next_page_url"`
}

func getDatabases(cfg *config.Config, id, key, organization string) ([]Database, error) {
	url := fmt.Sprintf("https://api.planetscale.com/v1/organizations/%s/databases", organization)

	client := analyzers.NewAnalyzeClient(cfg)

	databases := make([]Database, 0)

	// loop for pagination
	for url != "" {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", fmt.Sprintf("%s:%s", id, key))

		// Execute HTTP Request
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		// Check response status code
		switch resp.StatusCode {
		case http.StatusOK:
			// Decode response body
			var databasesResponse databasesJSON
			err = json.NewDecoder(resp.Body).Decode(&databasesResponse)
			if err != nil {
				return nil, err
			}

			databases = append(databases, databasesResponse.Data...)
			url = databasesResponse.NextPageUrl
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("invalid credentials")
		default:
			return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
		}
	}

	return databases, nil
}

type Branch struct {
	Id         string `json:"id"`
	Name       string `json:"name"`
	Production bool   `json:"production"`
}

type branchesJSON struct {
	Data []Branch `json:"data"`
}

func getDbBranches(cfg *config.Config, id, key, organization, db string) ([]Branch, error) {
	url := fmt.Sprintf("https://api.planetscale.com/v1/organizations/%s/databases/%s/branches", organization, db)

	client := analyzers.NewAnalyzeClient(cfg)

	branches := make([]Branch, 0)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("%s:%s", id, key))

	// Execute HTTP Request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check response status code
	switch resp.StatusCode {
	case http.StatusOK:
		// Decode response body
		var branchesResponse branchesJSON
		err = json.NewDecoder(resp.Body).Decode(&branchesResponse)
		if err != nil {
			return nil, err
		}

		branches = append(branches, branchesResponse.Data...)
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("invalid credentials")
	default:
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	return branches, nil
}

func printOrganizationPermissions(permissions []string) {
	color.Yellow("[i] Organization Permissions:")

	if len(permissions) == 0 {
		color.Yellow("No permissions found")
	} else {
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Permission"})
		for _, permission := range permissions {
			t.AppendRow(table.Row{color.GreenString(permission)})
		}
		t.Render()
	}
}

func printDatabasePermissions(permissions map[Database][]string) {
	color.Yellow("[i] Database Permissions:")

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Database", "Permission"})
	for database, dbPermissions := range permissions {
		t.AppendRow(table.Row{database.Name, color.GreenString(strings.Join(dbPermissions, ", "))})
	}
	t.Render()
}
