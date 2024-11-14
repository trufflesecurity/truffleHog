package output

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// JSONPrinter is a printer that prints results in JSON format.
type JSONPrinter struct{ mu sync.Mutex }

func (p *JSONPrinter) Print(_ context.Context, r *detectors.ResultWithMetadata) error {
	verificationErr := func(err error) string {
		if err != nil {
			return err.Error()
		}
		return ""
	}(r.VerificationError())

	v := &struct {
		// SourceMetadata contains source-specific contextual information.
		SourceMetadata *source_metadatapb.MetaData
		// SourceID is the ID of the source that the API uses to map secrets to specific sources.
		SourceID sources.SourceID
		// SourceType is the type of Source.
		SourceType sourcespb.SourceType
		// SourceName is the name of the Source.
		SourceName string
		// DetectorType is the type of Detector.
		DetectorType detectorspb.DetectorType
		// DetectorName is the string name of the DetectorType.
		DetectorName string
		// DetectorDescription is the description of the Detector.
		DetectorDescription string
		// DecoderName is the string name of the DecoderType.
		DecoderName       string
		Verified          bool
		VerificationError string `json:",omitempty"`
		// Raw contains the raw secret data.
		Raw string
		// RawV2 contains the raw secret identifier that is a combination of both the ID and the secret.
		// This is used for secrets that are multi part and could have the same ID. Ex: AWS credentials
		RawV2 string
		// Redacted contains the redacted version of the raw secret identification data for display purposes.
		// A secret ID should be used if available.
		Redacted       string
		ExtraData      map[string]string
		StructuredData *detectorspb.StructuredData
	}{
		SourceMetadata:      r.SourceMetadata,
		SourceID:            r.SourceID,
		SourceType:          r.SourceType,
		SourceName:          r.SourceName,
		DetectorType:        r.DetectorType,
		DetectorName:        r.DetectorType.String(),
		DetectorDescription: r.DetectorDescription,
		DecoderName:         r.DecoderType.String(),
		Verified:            r.Verified,
		VerificationError:   verificationErr,
		Raw:                 string(r.Raw),
		RawV2:               string(r.RawV2),
		Redacted:            r.Redacted,
		ExtraData:           r.ExtraData,
		StructuredData:      r.StructuredData,
	}
	out, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("could not marshal result: %w", err)
	}

	p.mu.Lock()
	fmt.Println(string(out))
	p.mu.Unlock()
	return nil
}
