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
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
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
		Bindings:     make([]analyzers.Binding, 0),
	}

	resource := analyzers.Resource{
		Name:               info.Organization.Name,
		FullyQualifiedName: "planetscale.com/organization/" + info.Organization.Id,
		Type:               "Organization",
	}

	for _, permission := range info.OrgPermissions {
		result.Bindings = append(result.Bindings, analyzers.Binding{
			Resource: resource,
			Permission: analyzers.Permission{
				Value: permission,
			},
		})
	}

	for db, permissions := range info.DBPermissions {
		dbResource := analyzers.Resource{
			Name:               db.Name,
			FullyQualifiedName: "planetscale.com/database/" + db.Id,
			Type:               "Database",
			Parent:             &resource,
		}
		for _, permission := range permissions {
			result.Bindings = append(result.Bindings, analyzers.Binding{
				Resource: dbResource,
				Permission: analyzers.Permission{
					Value: permission,
				},
			})
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
	DeployRequestScopes    []Scope       `json:"deploy_request_scopes"`
	BranchScopes           []BranchScope `json:"branch_scopes"`
	BackupScopes           []BranchScope `json:"backup_scopes"`
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
		// check if scope is for production or non production branch
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

func checkBackupPermissions(cfg *config.Config, scopes []BranchScope, id, key, organization, db, backupId string, production bool) ([]string, error) {
	permissions := make([]string, 0)
	for _, scope := range scopes {
		// check if scope is for production or non production branch
		if production != scope.Production {
			continue
		}
		scope.HttpTest.Payload = map[string]string{"backup_id": backupId}
		status, err := scope.HttpTest.RunTest(cfg, map[string]string{"Authorization": fmt.Sprintf("%s:%s", id, key)}, organization, db)
		if err != nil {
			return nil, fmt.Errorf("running test: %w", err)
		}
		if status {
			permissions = append(permissions, scope.Name)
		}
	}

	return permissions, nil
}

type SecretInfo struct {
	Organization          organization
	OrgPermissions        []string
	DBPermissions         map[Database][]string
	UnverifiedPermissions []string
}

func AnalyzeAndPrintPermissions(cfg *config.Config, id, token string) {
	info, err := AnalyzePermissions(cfg, id, token)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
		return
	}

	color.Green("[!] Valid PlanetScale credentials\n\n")
	color.Green("[i] Organization: %s\n\n", info.Organization.Name)
	printOrganizationPermissions(info.OrgPermissions)

	if len(info.DBPermissions) > 0 {
		printDatabasePermissions(info.DBPermissions)
	}

	printUnverifiedPermissions(info.UnverifiedPermissions)
}

func AnalyzePermissions(cfg *config.Config, id, token string) (*SecretInfo, error) {
	var info = &SecretInfo{}

	org, err := getOrganization(cfg, id, token)
	if err != nil {
		return nil, err
	}
	info.Organization = *org

	scopes, err := readInScopes()
	if err != nil {
		return nil, fmt.Errorf("reading in scopes: %w", err)
	}

	// organization permissions
	orgPermissions, err := getOrganizationPermissions(cfg, scopes, id, token, org.Name)
	if err != nil {
		return nil, err
	}
	info.OrgPermissions = orgPermissions

	// database permissions
	dbPermissions, err := getDatabasePermissions(cfg, scopes, id, token, org.Name)
	if err != nil {
		return nil, err
	}
	info.DBPermissions = dbPermissions

	// These are permissions that can not be verified,
	// either due to no endpoint available that specifically requires the permission
	// or there does not exist a way to verify these permissions without changing the state of the system (mostly DELETE permissions)
	info.UnverifiedPermissions = []string{
		PermissionStrings[ReadComment],
		PermissionStrings[CreateComment],
		PermissionStrings[ApproveDeployRequest],
		PermissionStrings[DeleteDatabases],
		PermissionStrings[DeleteDatabase],
		PermissionStrings[DeleteOauthTokens],
		PermissionStrings[DeleteBranch],
		PermissionStrings[DeleteBranchPassword],
		PermissionStrings[DeleteProductionBranch],
		PermissionStrings[DeleteProductionBranchPassword],
		PermissionStrings[DeleteBackups],
		PermissionStrings[DeleteProductionBranchBackups],
		PermissionStrings[WriteBackups],
	}

	return info, nil
}

type organization struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

type organizationJSON struct {
	Data []organization `json:"data"`
}

func getOrganization(cfg *config.Config, id, key string) (*organization, error) {
	url := "https://api.planetscale.com/v1/organizations"

	var organizationJSON organizationJSON
	err := sendGetRequest(cfg, id, key, url, &organizationJSON)
	if err != nil {
		return nil, err
	}

	if len(organizationJSON.Data) == 0 {
		return nil, errors.New("invalid api credentials")
	}

	return &organizationJSON.Data[0], nil
}

func getOrganizationPermissions(cfg *config.Config, scopes *Scopes, id, token, orgName string) ([]string, error) {
	organizationPermissions, err := checkPermissions(cfg, scopes.OrganizationScopes, id, token, orgName)
	if err != nil {
		return nil, err
	}

	oauthPermissions, err := getOAuthApplicationPermissions(cfg, scopes.OAuthApplicationScopes, id, token, orgName)
	if err != nil {
		return nil, err
	}
	organizationPermissions = append(organizationPermissions, oauthPermissions...)

	return organizationPermissions, nil
}

func getOAuthApplicationPermissions(cfg *config.Config, scopes []Scope, id, key, organization string) ([]string, error) {
	oauthApplicationId, err := getOAuthApplicationId(cfg, id, key, organization)
	if err != nil {
		return nil, err
	}

	if oauthApplicationId != "" {
		oauthPermissions, err := checkPermissions(cfg, scopes, id, key, organization, oauthApplicationId)
		if err != nil {
			return nil, err
		}
		return oauthPermissions, nil
	}
	return nil, nil
}

type oauthApplicationJSON struct {
	Data []struct {
		Id string `json:"id"`
	}
}

func getOAuthApplicationId(cfg *config.Config, id, key, organization string) (string, error) {
	url := fmt.Sprintf("https://api.planetscale.com/v1/organizations/%s/oauth-applications", organization)

	var oauthApplicationJSON oauthApplicationJSON
	err := sendGetRequest(cfg, id, key, url, &oauthApplicationJSON)
	if err != nil {
		return "", err
	}

	if len(oauthApplicationJSON.Data) > 0 {
		return oauthApplicationJSON.Data[0].Id, nil
	}
	return "", nil // no oauth application found
}

func getDatabasePermissions(cfg *config.Config, scopes *Scopes, id, token, orgName string) (map[Database][]string, error) {
	databases, err := getDatabases(cfg, id, token, orgName)
	if err != nil {
		return nil, err
	}

	dbPermissionsMap := make(map[Database][]string)
	for _, database := range databases {
		dbPermissions, err := checkPermissions(cfg, scopes.DatabaseScopes, id, token, orgName, database.Name)
		if err != nil {
			return nil, err
		}
		dbPermissionsMap[database] = dbPermissions

		branchPermissions, err := getBranchPermissions(cfg, scopes, id, token, orgName, database.Name)
		if err != nil {
			return nil, err
		}
		dbPermissionsMap[database] = append(dbPermissionsMap[database], branchPermissions...)
	}

	return dbPermissionsMap, nil
}

func getBranchPermissions(cfg *config.Config, scopes *Scopes, id, token, orgName, dbName string) ([]string, error) {
	branches, err := getDbBranches(cfg, id, token, orgName, dbName)
	if err != nil {
		return nil, err
	}

	// get permissions for prod and non prod branches
	prodDone, nonProdDone := false, false
	allBranchPermissions := make([]string, 0)
	for _, branch := range branches {
		// check if we have already checked permissions for prod or non prod branches
		if (prodDone && branch.Production) || (nonProdDone && !branch.Production) {
			continue
		}

		if branch.Production {
			prodDone = true
		} else {
			nonProdDone = true
		}

		branchPermissions, err := checkBranchPermissions(cfg, scopes.BranchScopes, id, token, orgName, dbName, branch.Name, branch.Production)
		if err != nil {
			return nil, err
		}
		allBranchPermissions = append(allBranchPermissions, branchPermissions...)

		backupId, err := getBackupId(cfg, id, token, orgName, dbName, branch.Name)
		if err != nil {
			return nil, err
		}

		if backupId != "" {
			backupPermissions, err := checkBackupPermissions(cfg, scopes.BackupScopes, id, token, orgName, dbName, backupId, branch.Production)
			if err != nil {
				return nil, err
			}
			allBranchPermissions = append(allBranchPermissions, backupPermissions...)
		}

		if prodDone && nonProdDone {
			break
		}
	}

	return allBranchPermissions, err
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
	databases := make([]Database, 0)

	// loop for pagination
	for url != "" {
		var databasesResponse databasesJSON
		err := sendGetRequest(cfg, id, key, url, &databasesResponse)
		if err != nil {
			return nil, err
		}

		databases = append(databases, databasesResponse.Data...)
		url = databasesResponse.NextPageUrl
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
	var branchesResponse branchesJSON
	err := sendGetRequest(cfg, id, key, url, &branchesResponse)
	if err != nil {
		return nil, err
	}
	return branchesResponse.Data, nil
}

type backupsJson struct {
	Data []struct {
		Id string `json:"id"`
	}
}

func getBackupId(cfg *config.Config, id, key, organization, db, branch string) (string, error) {
	url := fmt.Sprintf("https://api.planetscale.com/v1/organizations/%s/databases/%s/branches/%s/backups", organization, db, branch)
	var backupsResponse backupsJson
	err := sendGetRequest(cfg, id, key, url, &backupsResponse)
	if err != nil {
		return "", err
	}
	if len(backupsResponse.Data) > 0 {
		return backupsResponse.Data[0].Id, nil
	}
	return "", nil // no backups found
}

func sendGetRequest(cfg *config.Config, id, key, url string, responseObj interface{}) error {
	client := analyzers.NewAnalyzeClient(cfg)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("%s:%s", id, key))

	// Execute HTTP Request
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check response status code
	switch resp.StatusCode {
	case http.StatusOK:
		// Decode response body
		err = json.NewDecoder(resp.Body).Decode(&responseObj)
		if err != nil {
			return err
		}
		return nil // response successfully decoded
	case http.StatusForbidden:
		return nil // no permission
	default:
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
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

func printUnverifiedPermissions(permissions []string) {
	color.Yellow("[i] Unverified Permissions:")

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Permission"})
	for _, permission := range permissions {
		t.AppendRow(table.Row{color.YellowString(permission)})
	}
	t.Render()
}
