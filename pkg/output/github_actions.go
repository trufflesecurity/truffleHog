package output

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

var dedupeCache = make(map[string]struct{})

// GitHubActionsPrinter is a printer that prints results in GitHub Actions format.
type GitHubActionsPrinter struct{ mu sync.Mutex }

func (p *GitHubActionsPrinter) Print(_ context.Context, r *detectors.ResultWithMetadata) error {
	out := gitHubActionsOutputFormat{
		DetectorType:        r.Result.DetectorType.String(),
		DetectorDescription: r.DetectorDescription,
		DecoderType:         r.DecoderType.String(),
		Verified:            r.Result.Verified,
	}

	meta, err := structToMap(r.SourceMetadata.Data)
	if err != nil {
		return fmt.Errorf("could not marshal result: %w", err)
	}

	for _, data := range meta {
		for k, v := range data {
			if k == "line" {
				if line, ok := v.(float64); ok {
					out.StartLine = int64(line)
				}
			}
			if k == "file" {
				if filename, ok := v.(string); ok {
					out.Filename = filename
				}
			}
		}
	}

	verifiedStatus := "unverified"
	if out.Verified {
		verifiedStatus = "verified"
	}

	key := fmt.Sprintf("%s:%s:%s:%s:%d", out.DecoderType, out.DetectorType, verifiedStatus, out.Filename, out.StartLine)
	h := sha256.New()
	h.Write([]byte(key))
	key = hex.EncodeToString(h.Sum(nil))
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := dedupeCache[key]; ok {
		return nil
	}
	dedupeCache[key] = struct{}{}

	name := ""
	if nameValue, ok := r.Result.ExtraData["name"]; ok {
		name = fmt.Sprintf(" (%s)", nameValue)
	}

	message := fmt.Sprintf("Found %s %s%s result 🐷🔑\n", verifiedStatus, out.DetectorType, name)
	if r.DecoderType != detectorspb.DecoderType_PLAIN {
		message = fmt.Sprintf("Found %s %s%s result with %s encoding 🐷🔑\n", verifiedStatus, out.DetectorType, name, out.DecoderType)
	}

	fmt.Printf("::warning file=%s,line=%d,endLine=%d::%s",
		out.Filename, out.StartLine, out.StartLine, message)

	return nil
}

type gitHubActionsOutputFormat struct {
	DetectorType        string
	DetectorDescription string
	DecoderType         string
	Verified            bool
	StartLine           int64
	Filename            string
}
