package openai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/pb/analyzerpb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzerpb.AnalyzerType { return analyzerpb.AnalyzerType_OpenAI }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	info, err := AnalyzePermissions(a.Cfg, credInfo["key"])
	if err != nil {
		return nil, err
	}
	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *AnalyzerJSON) *analyzers.AnalyzerResult {
	result := analyzers.AnalyzerResult{
		Metadata: map[string]any{
			"user":          info.me.Name,
			"email":         info.me.Email,
			"mfa":           strconv.FormatBool(info.me.MfaEnabled),
			"is_admin":      strconv.FormatBool(info.isAdmin),
			"is_restricted": strconv.FormatBool(info.isRestricted),
		},
	}

	perms := convertPermissions(info.isAdmin, info.perms)
	for _, org := range info.me.Orgs.Data {
		resource := analyzers.Resource{
			Name:               org.Title,
			FullyQualifiedName: org.ID,
			Type:               "organization",
			Metadata: map[string]any{
				"description": org.Description,
				"user":        org.User,
			},
		}
		// Copy each permission into this resource.
		result.Bindings = append(result.Bindings, analyzers.BindAllPermissions(resource, perms...)...)
	}

	return &result
}

func convertPermissions(isAdmin bool, perms []permissionData) []analyzers.Permission {
	var permissions []analyzers.Permission

	if isAdmin {
		permissions = append(permissions, analyzers.Permission{Value: analyzers.FullAccess})
	} else {
		for _, perm := range perms {
			permName := perm.name + ":" + string(perm.status)
			permissions = append(permissions, analyzers.Permission{Value: permName})
		}
	}

	return permissions
}

const (
	BASE_URL      = "https://api.openai.com"
	ORGS_ENDPOINT = "/v1/organizations"
	ME_ENDPOINT   = "/v1/me"
)

type MeJSON struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	Phone      string `json:"phone_number"`
	MfaEnabled bool   `json:"mfa_flag_enabled"`
	Orgs       struct {
		Data []struct {
			ID          string `json:"id"`
			Title       string `json:"title"`
			User        string `json:"name"`
			Description string `json:"description"`
			Personal    bool   `json:"personal"`
			Default     bool   `json:"is_default"`
			Role        string `json:"role"`
		} `json:"data"`
	} `json:"orgs"`
}

type permissionData struct {
	name      string
	endpoints []string
	status    analyzers.PermissionType
}

type AnalyzerJSON struct {
	me           MeJSON
	isAdmin      bool
	isRestricted bool
	perms        []permissionData
}

var POST_PAYLOAD = map[string]interface{}{"speed": 1}

func AnalyzeAndPrintPermissions(cfg *config.Config, apiKey string) {
	data, err := AnalyzePermissions(cfg, apiKey)
	if err != nil {
		color.Red("[x] %s", err.Error())
		return
	}
	color.Green("[!] Valid OpenAI Token\n\n")

	printUserData(data.me)
	if data.isAdmin {
		color.Green("[!] Admin API Key. All permissions available.")
	} else if data.isRestricted {
		color.Yellow("[!] Restricted API Key. Limited permissions available.")
		printPermissions(data.perms, cfg.ShowAll)
	}
}

// AnalyzePermissions will analyze the permissions of an OpenAI API key
func AnalyzePermissions(cfg *config.Config, key string) (*AnalyzerJSON, error) {
	data := AnalyzerJSON{
		isAdmin:      false,
		isRestricted: false,
	}

	meJSON, err := getUserData(cfg, key)
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}
	data.me = meJSON

	isAdmin, err := checkAdminKey(cfg, key)
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}

	if isAdmin {
		data.isAdmin = true
	} else {
		data.isRestricted = true
		if err := analyzeScopes(key); err != nil {
			return nil, fmt.Errorf(err.Error())
		}
		data.perms = getPermissions()
	}

	return &data, nil
}

func analyzeScopes(key string) error {
	for _, scope := range SCOPES {
		if err := scope.RunTests(key); err != nil {
			return err
		}
	}
	return nil
}

func openAIRequest(cfg *config.Config, method string, url string, key string, data map[string]interface{}) ([]byte, *http.Response, error) {
	var inBody io.Reader
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return nil, nil, err
		}
		inBody = bytes.NewBuffer(jsonData)
	}

	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest(method, url, inBody)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Add("Authorization", "Bearer "+key)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}

	defer resp.Body.Close()

	outBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	return outBody, resp, nil
}

func checkAdminKey(cfg *config.Config, key string) (bool, error) {
	// Check for all permissions
	//nolint:bodyclose
	_, resp, err := openAIRequest(cfg, "GET", BASE_URL+ORGS_ENDPOINT, key, nil)
	if err != nil {
		return false, err
	}
	switch resp.StatusCode {
	case 200:
		return true, nil
	case 403:
		return false, nil
	default:
		return false, err
	}
}

func getUserData(cfg *config.Config, key string) (MeJSON, error) {
	var meJSON MeJSON
	//nolint:bodyclose
	me, resp, err := openAIRequest(cfg, "GET", BASE_URL+ME_ENDPOINT, key, nil)
	if err != nil {
		return meJSON, err
	}

	if resp.StatusCode != 200 {
		return meJSON, fmt.Errorf("invalid OpenAI token")
	}

	// Marshall me into meJSON struct
	if err := json.Unmarshal(me, &meJSON); err != nil {
		return meJSON, err
	}
	return meJSON, nil
}

func printUserData(meJSON MeJSON) {
	color.Green("[i] User: %v", meJSON.Name)
	color.Green("[i] Email: %v", meJSON.Email)
	color.Green("[i] Phone: %v", meJSON.Phone)
	color.Green("[i] MFA Enabled: %v", meJSON.MfaEnabled)

	if len(meJSON.Orgs.Data) > 0 {
		color.Green("[i] Organizations:")
		for _, org := range meJSON.Orgs.Data {
			color.Green("  - %v", org.Title)
		}
	}
	fmt.Print("\n\n")
}

func stringifyPermissionStatus(tests []analyzers.HttpStatusTest) analyzers.PermissionType {
	readStatus := false
	writeStatus := false
	errors := false
	for _, test := range tests {
		if test.Type == analyzers.READ {
			readStatus = test.Status.Value
		} else if test.Type == analyzers.WRITE {
			writeStatus = test.Status.Value
		}
		if test.Status.IsError {
			errors = true
		}
	}
	if errors {
		return analyzers.ERROR
	}
	if readStatus && writeStatus {
		return analyzers.READ_WRITE
	} else if readStatus {
		return analyzers.READ
	} else if writeStatus {
		return analyzers.WRITE
	} else {
		return analyzers.NONE
	}
}

func getPermissions() []permissionData {
	var perms []permissionData

	for _, scope := range SCOPES {
		status := stringifyPermissionStatus(scope.Tests)
		perms = append(perms, permissionData{
			name:      scope.Name,
			endpoints: scope.Endpoints,
			status:    status,
		})
	}

	return perms
}

func printPermissions(perms []permissionData, show_all bool) {
	fmt.Print("\n\n")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Scope", "Endpoints", "Permission"})

	for _, perm := range perms {
		if show_all || perm.status != analyzers.NONE {
			t.AppendRow([]interface{}{perm.name, perm.endpoints[0], perm.status})

			for i := 1; i < len(perm.endpoints); i++ {
				t.AppendRow([]interface{}{"", perm.endpoints[i], perm.status})
			}
		}
	}

	t.Render()
	fmt.Print("\n\n")
}
