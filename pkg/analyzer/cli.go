package analyzer

import (
	"strings"

	"github.com/alecthomas/kingpin/v2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/airbrake"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/airtable"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/anthropic"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/asana"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/bitbucket"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/dockerhub"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/gitlab"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/huggingface"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/mailchimp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/mailgun"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/mysql"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/notion"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/openai"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/opsgenie"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/planetscale"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/postgres"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/postman"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/privatekey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/sendgrid"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/shopify"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/slack"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/sourcegraph"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/square"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/stripe"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/twilio"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

type SecretInfo struct {
	Parts map[string]string
	Cfg   *config.Config
}

func Command(app *kingpin.Application) *kingpin.CmdClause {
	return app.Command("analyze", "Analyze API keys for fine-grained permissions information.")
}

func Run(keyType string, secretInfo SecretInfo) {
	if secretInfo.Cfg == nil {
		secretInfo.Cfg = &config.Config{}
	}
	switch strings.ToLower(keyType) {
	case "github":
		github.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "sendgrid":
		sendgrid.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "openai":
		openai.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "postgres":
		postgres.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "mysql":
		mysql.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "slack":
		slack.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "twilio":
		twilio.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["sid"], secretInfo.Parts["key"])
	case "airbrake":
		airbrake.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "huggingface":
		huggingface.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "stripe":
		stripe.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "gitlab":
		gitlab.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "mailchimp":
		mailchimp.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "postman":
		postman.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "bitbucket":
		bitbucket.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "asana":
		asana.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "mailgun":
		mailgun.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "square":
		square.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "sourcegraph":
		sourcegraph.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "shopify":
		shopify.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"], secretInfo.Parts["url"])
	case "opsgenie":
		opsgenie.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "privatekey":
		privatekey.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "notion":
		notion.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "dockerhub":
		dockerhub.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["username"], secretInfo.Parts["pat"])
	case "anthropic":
		anthropic.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "airtable":
		airtable.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "planetscale":
		planetscale.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["id"], secretInfo.Parts["token"])
	}
}
