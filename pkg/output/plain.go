package output

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/fatih/color"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
)

var (
	yellowPrinter    = color.New(color.FgYellow)
	greenPrinter     = color.New(color.FgHiGreen)
	boldGreenPrinter = color.New(color.Bold, color.FgHiGreen)
	whitePrinter     = color.New(color.FgWhite)
	boldWhitePrinter = color.New(color.Bold, color.FgWhite)
)

// PlainPrinter is a printer that prints results in plain text format.
type PlainPrinter struct{ mu sync.Mutex }

func (p *PlainPrinter) Print(_ context.Context, r *detectors.ResultWithMetadata) error {
	out := outputFormat{
		DetectorType:        r.Result.DetectorType.String(),
		DecoderType:         r.DecoderType.String(),
		Verified:            r.Result.Verified,
		VerificationError:   r.Result.VerificationError(),
		MetaData:            r.SourceMetadata,
		Raw:                 strings.TrimSpace(string(r.Result.Raw)),
		DetectorDescription: r.DetectorDescription,
	}

	meta, err := structToMap(out.MetaData.Data)
	if err != nil {
		return fmt.Errorf("could not marshal result: %w", err)
	}

	printer := greenPrinter
	p.mu.Lock()
	defer p.mu.Unlock()

	if out.Verified {
		boldGreenPrinter.Print("✅ Found verified result 🐷🔑\n")
	} else {
		printer = whitePrinter
		boldWhitePrinter.Print("Found unverified result 🐷🔑❓\n")
		if out.VerificationError != nil {
			yellowPrinter.Printf("Verification issue: %s\n", out.VerificationError)
		}
	}
	printer.Printf("Detector Type: %s\n", out.DetectorType)
	printer.Printf("Decoder Type: %s\n", out.DecoderType)
	printer.Printf("Raw result: %s\n", whitePrinter.Sprint(out.Raw))

	for k, v := range r.Result.ExtraData {
		printer.Printf(
			"%s: %v\n",
			cases.Title(language.AmericanEnglish).String(k),
			v)
	}

	if r.Result.StructuredData != nil {
		for idx, v := range r.Result.StructuredData.GithubSshKey {
			printer.Printf("GithubSshKey %d User: %s\n", idx, v.User)

			if v.PublicKeyFingerprint != "" {
				printer.Printf("GithubSshKey %d Fingerprint: %s\n", idx, v.PublicKeyFingerprint)
			}
		}

		for idx, v := range r.Result.StructuredData.TlsPrivateKey {
			printer.Printf("TlsPrivateKey %d Fingerprint: %s\n", idx, v.CertificateFingerprint)
			printer.Printf("TlsPrivateKey %d Verification URL: %s\n", idx, v.VerificationUrl)
			printer.Printf("TlsPrivateKey %d Expiration: %d\n", idx, v.ExpirationTimestamp)
		}
	}

	aggregateData := make(map[string]any)
	var aggregateDataKeys []string

	for _, data := range meta {
		for k, v := range data {
			aggregateDataKeys = append(aggregateDataKeys, k)
			aggregateData[k] = v
		}
	}
	sort.Strings(aggregateDataKeys)
	for _, k := range aggregateDataKeys {
		printer.Printf("%s: %v\n", cases.Title(language.AmericanEnglish).String(k), aggregateData[k])
	}
	fmt.Println("")
	return nil
}

func structToMap(obj any) (m map[string]map[string]any, err error) {
	data, err := json.Marshal(obj)
	if err != nil {
		return
	}
	err = json.Unmarshal(data, &m)
	return
}

type outputFormat struct {
	DetectorType,
	DecoderType string
	Verified          bool
	VerificationError error
	Raw               string
	*source_metadatapb.MetaData
	DetectorDescription string
}
