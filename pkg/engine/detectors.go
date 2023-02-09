package engine

import (
	"reflect"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

// Detectors only returns a specific set of detectors.
func Detectors(ctx context.Context, dts []string) []detectors.Detector {
	defaultDetectors := DefaultDetectors()
	if len(dts) == 0 {
		return defaultDetectors
	}

	configured := setDetectors(ctx, dts)

	if len(configured) == 0 {
		ctx.Logger().Info("no valid detectors specified, using default set")
		return defaultDetectors
	}

	return filterDetectors(dts, defaultDetectors, configured)
}

func setDetectors(ctx context.Context, dts []string) map[string]struct{} {
	valid := make(map[string]struct{}, len(dts))
	for _, d := range dts {
		ctx.Logger().Info("setting detector", "detector-name", d)
		valid[strings.ToLower(d)] = struct{}{}
	}

	return valid
}

func filterDetectors(dts []string, defaultDetectors []detectors.Detector, configured map[string]struct{}) []detectors.Detector {
	ds := make([]detectors.Detector, 0, len(dts))
	for _, d := range defaultDetectors {
		dt := strings.TrimLeft(reflect.TypeOf(d).String(), "*")
		idx := strings.LastIndex(dt, ".")
		dt = dt[:idx]

		if _, ok := configured[dt]; ok {
			ds = append(ds, d)
		}
	}

	return ds
}
