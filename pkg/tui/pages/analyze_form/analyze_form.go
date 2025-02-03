package analyze_form

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
)

var (
	titleStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFDF5")).
		Background(lipgloss.Color(styles.Colors["bronze"])).
		Padding(0, 1)
)

type AnalyzeForm struct {
	common.Common
	KeyType string
	form    textinputs.Model
}

type Submission struct {
	AnalyzerType string
	AnalyzerInfo analyzer.SecretInfo
}

func New(c common.Common, keyType string) *AnalyzeForm {
	var inputs []textinputs.InputConfig
	switch strings.ToLower(keyType) {
	case "twilio":
		inputs = []textinputs.InputConfig{{
			Label:    "SID",
			Key:      "sid",
			Required: true,
		}, {
			Label:       "Token",
			Key:         "key",
			Required:    true,
			RedactInput: true,
		}}
	case "shopify":
		inputs = []textinputs.InputConfig{{
			Label:       "Secret",
			Key:         "key",
			Required:    true,
			RedactInput: true,
		}, {
			Label:    "Shopify URL",
			Key:      "url",
			Required: true,
		}}
	case "dockerhub":
		inputs = []textinputs.InputConfig{{
			Label:    "Username",
			Key:      "username",
			Required: true,
		}, {
			Label:       "Token(PAT)",
			Key:         "pat",
			Required:    true,
			RedactInput: true,
		}}
	case "planetscale":
		inputs = []textinputs.InputConfig{{
			Label:    "Service Id",
			Key:      "id",
			Required: true,
		}, {
			Label:       "Service Token",
			Key:         "token",
			Required:    true,
			RedactInput: true,
		}}
	default:
		inputs = []textinputs.InputConfig{{
			Label:       "Secret",
			Key:         "key",
			Required:    true,
			RedactInput: true,
		}}
	}

	// Always append a log file option.
	inputs = append(inputs, textinputs.InputConfig{
		Label: "Log file",
		Help:  "Log HTTP requests that analysis performs to this file",
		Key:   "log_file",
	})

	form := textinputs.New(inputs).
		SetHeader(titleStyle.Render(fmt.Sprintf("Configuring %s analyzer", keyType))).
		SetFooter("⚠️  Running TruffleHog Analyze will send a lot of requests ⚠️\n\n🚧 Please confirm you have permission to run TruffleHog Analyze against this secret 🚧").
		SetSubmitMsg("Run TruffleHog Analyze")
	return &AnalyzeForm{
		Common:  c,
		KeyType: keyType,
		form:    form,
	}
}

func (AnalyzeForm) Init() tea.Cmd {
	return nil
}

type SetAnalyzerMsg string

func (ui *AnalyzeForm) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case SetAnalyzerMsg:
		ui = New(ui.Common, string(msg))
		return ui, nil
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, ui.Common.KeyMap.Back):
			return nil, tea.Quit
		}
	}

	if _, ok := msg.(textinputs.SelectNextMsg); ok {
		values := make(map[string]string)
		for k, v := range ui.form.GetInputs() {
			values[k] = v.Value
		}
		secretInfoCmd := func() tea.Msg {
			// TODO: Set Config
			logFile := values["log_file"]
			cfg := config.Config{
				LogFile:        logFile,
				LoggingEnabled: logFile != "",
			}
			return Submission{
				AnalyzerType: ui.KeyType,
				AnalyzerInfo: analyzer.SecretInfo{Cfg: &cfg, Parts: values},
			}
		}
		return ui, secretInfoCmd
	}

	form, cmd := ui.form.Update(msg)
	ui.form = form.(textinputs.Model)
	return ui, cmd
}

func (ui *AnalyzeForm) View() string {
	return styles.AppStyle.Render(ui.form.View())
}

func (m *AnalyzeForm) ShortHelp() []key.Binding {
	// TODO: actually return something
	return nil
}

func (m *AnalyzeForm) FullHelp() [][]key.Binding {
	// TODO: actually return something
	return nil
}
