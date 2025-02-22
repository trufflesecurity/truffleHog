package analyzers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sort"

	"github.com/fatih/color"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type (
	Analyzer interface {
		Type() AnalyzerType
		Analyze(ctx context.Context, credentialInfo map[string]string) (*AnalyzerResult, error)
	}

	AnalyzerType int

	// AnalyzerResult is the output of analysis.
	AnalyzerResult struct {
		AnalyzerType       AnalyzerType
		Bindings           []Binding
		UnboundedResources []Resource
		Metadata           map[string]any
	}

	Resource struct {
		Name               string
		FullyQualifiedName string
		Type               string
		Metadata           map[string]any
		Parent             *Resource
	}

	Permission struct {
		Value  string
		Parent *Permission
	}

	Binding struct {
		Resource   Resource
		Permission Permission
	}
)

type PermissionType string

const (
	READ       PermissionType = "Read"
	WRITE      PermissionType = "Write"
	READ_WRITE PermissionType = "Read & Write"
	NONE       PermissionType = "None"
	ERROR      PermissionType = "Error"

	FullAccess string = "full_access"
)

const (
	AnalyzerTypeInvalid AnalyzerType = iota
	AnalyzerTypeAirbrake
	AnalyzerAnthropic
	AnalyzerTypeAsana
	AnalyzerTypeBitbucket
	AnalyzerTypeDockerHub
	AnalyzerTypeGitHub
	AnalyzerTypeGitLab
	AnalyzerTypeHuggingFace
	AnalyzerTypeMailchimp
	AnalyzerTypeMailgun
	AnalyzerTypeMySQL
	AnalyzerTypeOpenAI
	AnalyzerTypeOpsgenie
	AnalyzerTypePostgres
	AnalyzerTypePostman
	AnalyzerTypeSendgrid
	AnalyzerTypeShopify
	AnalyzerTypeSlack
	AnalyzerTypeSourcegraph
	AnalyzerTypeSquare
	AnalyzerTypeStripe
	AnalyzerTypeTwilio
	AnalyzerTypePrivateKey
	AnalyzerTypeNotion
	AnalyzerTypeAirtable
	AnalyzerTypePlanetScale
	// Add new items here with AnalyzerType prefix
)

// analyzerTypeStrings maps the enum to its string representation.
var analyzerTypeStrings = map[AnalyzerType]string{
	AnalyzerTypeInvalid:     "Invalid",
	AnalyzerTypeAirbrake:    "Airbrake",
	AnalyzerTypeAirtable:    "Airtable",
	AnalyzerAnthropic:       "Anthropic",
	AnalyzerTypeAsana:       "Asana",
	AnalyzerTypeBitbucket:   "Bitbucket",
	AnalyzerTypeDockerHub:   "DockerHub",
	AnalyzerTypeGitHub:      "GitHub",
	AnalyzerTypeGitLab:      "GitLab",
	AnalyzerTypeHuggingFace: "HuggingFace",
	AnalyzerTypeMailchimp:   "Mailchimp",
	AnalyzerTypeMailgun:     "Mailgun",
	AnalyzerTypeMySQL:       "MySQL",
	AnalyzerTypeOpenAI:      "OpenAI",
	AnalyzerTypeOpsgenie:    "Opsgenie",
	AnalyzerTypePostgres:    "Postgres",
	AnalyzerTypePostman:     "Postman",
	AnalyzerTypeSendgrid:    "Sendgrid",
	AnalyzerTypeShopify:     "Shopify",
	AnalyzerTypeSlack:       "Slack",
	AnalyzerTypeSourcegraph: "Sourcegraph",
	AnalyzerTypeSquare:      "Square",
	AnalyzerTypeStripe:      "Stripe",
	AnalyzerTypeTwilio:      "Twilio",
	AnalyzerTypePrivateKey:  "PrivateKey",
	AnalyzerTypeNotion:      "Notion",
	AnalyzerTypePlanetScale: "PlanetScale",
	// Add new mappings here
}

// String method to get the string representation of an AnalyzerType.
func (a AnalyzerType) String() string {
	if str, ok := analyzerTypeStrings[a]; ok {
		return str
	}
	return "Unknown"
}

// GetSortedAnalyzerTypes returns a sorted slice of AnalyzerType strings, skipping "Invalid".
func AvailableAnalyzers() []string {
	var analyzerStrings []string

	// Iterate through the map to collect all string values except "Invalid".
	for typ, str := range analyzerTypeStrings {
		if typ != AnalyzerTypeInvalid {
			analyzerStrings = append(analyzerStrings, str)
		}
	}

	// Sort the slice alphabetically.
	sort.Strings(analyzerStrings)

	return analyzerStrings
}

type PermissionStatus struct {
	Value   bool
	IsError bool
}

type HttpStatusTest struct {
	URL     string
	Method  string
	Payload map[string]interface{}
	Params  map[string]string
	Valid   []int
	Invalid []int
	Type    PermissionType
	Status  PermissionStatus
	Risk    string
}

func (h *HttpStatusTest) RunTest(headers map[string]string) error {
	// If body data, marshal to JSON
	var data io.Reader
	if h.Payload != nil {
		jsonData, err := json.Marshal(h.Payload)
		if err != nil {
			return err
		}
		data = bytes.NewBuffer(jsonData)
	}

	// Create new HTTP request
	client := &http.Client{}
	req, err := http.NewRequest(h.Method, h.URL, data)
	if err != nil {
		return err
	}

	// Add custom headers if provided
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Execute HTTP Request
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check response status code
	switch {
	case StatusContains(resp.StatusCode, h.Valid):
		h.Status.Value = true
	case StatusContains(resp.StatusCode, h.Invalid):
		h.Status.Value = false
	default:
		h.Status.IsError = true
	}
	return nil
}

type Scope struct {
	Name  string
	Tests []interface{}
}

func StatusContains(status int, vals []int) bool {
	for _, v := range vals {
		if status == v {
			return true
		}
	}
	return false
}

func GetWriterFromStatus(status PermissionType) func(a ...interface{}) string {
	switch status {
	case READ:
		return color.New(color.FgYellow).SprintFunc()
	case WRITE:
		return color.New(color.FgGreen).SprintFunc()
	case READ_WRITE:
		return color.New(color.FgGreen).SprintFunc()
	case NONE:
		return color.New().SprintFunc()
	case ERROR:
		return color.New(color.FgRed).SprintFunc()
	default:
		return color.New().SprintFunc()
	}
}

var GreenWriter = color.New(color.FgGreen).SprintFunc()
var YellowWriter = color.New(color.FgYellow).SprintFunc()
var RedWriter = color.New(color.FgRed).SprintFunc()
var DefaultWriter = color.New().SprintFunc()

// BindAllPermissions creates a Binding for each permission to the given
// resource.
func BindAllPermissions(r Resource, perms ...Permission) []Binding {
	bindings := make([]Binding, len(perms))
	for i, perm := range perms {
		bindings[i] = Binding{
			Resource:   r,
			Permission: perm,
		}
	}
	return bindings
}
