//go:build detectors
// +build detectors

package generic

import (
	"context"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

func TestGeneric_FromChunk(t *testing.T) {
	ctx := context.Background()
	s := New()

	found := []string{
		"export CONFIG_SERVICE_PASSWORD=34t98hofi2309pr230",
		"CONFIG_SERVICE_PASSWORD: 34t98hofi2309pr230",
		"the secret is 34t98hofi2309pr230", // keyword within distance of cred-looking token
	}
	notFound := []string{
		"export MAGIC_VAR=piggymetrics201925",              // key does not have keyword
		"export CONFIG_SERVICE_PASSWORD=testcredentials",   // has test, cred
		"export CONFIG_SERVICE_PASSWORD=password123",       // has pass
		"export CONFIG_SERVICE_PASSWORD=too-plain",         // no digit
		"export CONFIG_SERVICE_PASSWORD=abcdefg123",        // known FP
		"SECRET: mountain422",                              // excluded by word list
		"secret_guid=3fc0b7f7-da09-4ae7-a9c8-d69824b1819b", // excluded by matcher
		"secret_issue_key: BLAH-23490",                     // excluded by matcher
	}

	for _, data := range found {
		got, _ := s.FromData(ctx, false, []byte(data))
		if len(got) == 0 {
			t.Errorf("Generic.FromData() expected secret for data: %s", data)
			return
		}
	}

	for _, data := range notFound {
		got, _ := s.FromData(ctx, false, []byte(data))
		if len(got) != 0 {
			t.Errorf("Generic.FromData() expected no secret for data: %s", data)
			return
		}
	}
}

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := New()
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(name, func(b *testing.B) {
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				_, err := s.FromData(ctx, false, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
