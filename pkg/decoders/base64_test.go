package decoders

import (
	"testing"

	"github.com/kylelemons/godebug/pretty"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestBase64_FromChunk(t *testing.T) {
	tests := []struct {
		chunk *sources.Chunk
		want  *sources.Chunk
		name  string
	}{
		{
			name: "only b64 chunk",
			chunk: &sources.Chunk{
				Data: []byte(`bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=`),
			},
			want: &sources.Chunk{
				Data: []byte(`longer-encoded-secret-test`),
			},
		},
		{
			name: "mixed content",
			chunk: &sources.Chunk{
				Data: []byte(`token: bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=`),
			},
			want: &sources.Chunk{
				Data: []byte(`token: longer-encoded-secret-test`),
			},
		},
		{
			name: "no chunk",
			chunk: &sources.Chunk{
				Data: []byte(``),
			},
			want: nil,
		},
		{
			name: "env var (looks like all b64 decodable but has `=` in the middle)",
			chunk: &sources.Chunk{
				Data: []byte(`some-encoded-secret=dGVzdHNlY3JldA==`),
			},
			want: &sources.Chunk{
				Data: []byte(`some-encoded-secret=testsecret`),
			},
		},
		{
			name: "has longer b64 inside",
			chunk: &sources.Chunk{
				Data: []byte(`some-encoded-secret="bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q="`),
			},
			want: &sources.Chunk{
				Data: []byte(`some-encoded-secret="longer-encoded-secret-test"`),
			},
		},
		{
			name: "many possible substrings",
			chunk: &sources.Chunk{
				Data: []byte(`Many substrings in this slack message could be base64 decoded
				but only dGhpcyBlbmNhcHN1bGF0ZWQgc2VjcmV0 should be decoded.`),
			},
			want: &sources.Chunk{
				Data: []byte(`Many substrings in this slack message could be base64 decoded
				but only this encapsulated secret should be decoded.`),
			},
		},
		{
			name: "b64-url-safe: only b64 chunk",
			chunk: &sources.Chunk{
				Data: []byte(`bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q`),
			},
			want: &sources.Chunk{
				Data: []byte(`longer-encoded-secret-test`),
			},
		},
		{
			name: "b64-url-safe: mixed content",
			chunk: &sources.Chunk{
				Data: []byte(`token: bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q`),
			},
			want: &sources.Chunk{
				Data: []byte(`token: longer-encoded-secret-test`),
			},
		},
		{
			name: "b64-url-safe: env var (looks like all b64 decodable but has `=` in the middle)",
			chunk: &sources.Chunk{
				Data: []byte(`some-encoded-secret=dGVzdHNlY3JldA`),
			},
			want: &sources.Chunk{
				Data: []byte(`some-encoded-secret=testsecret`),
			},
		},
		{
			name: "b64-url-safe: has longer b64 inside",
			chunk: &sources.Chunk{
				Data: []byte(`some-encoded-secret="bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q"`),
			},
			want: &sources.Chunk{
				Data: []byte(`some-encoded-secret="longer-encoded-secret-test"`),
			},
		},
		{
			name: "b64-url-safe: hyphen url b64",
			chunk: &sources.Chunk{
				Data: []byte(`dHJ1ZmZsZWhvZz4-ZmluZHMtc2VjcmV0cw`),
			},
			want: &sources.Chunk{
				Data: []byte(`trufflehog>>finds-secrets`),
			},
		},
		{
			name: "b64-url-safe: underscore url b64",
			chunk: &sources.Chunk{
				Data: []byte(`YjY0dXJsc2FmZS10ZXN0LXNlY3JldC11bmRlcnNjb3Jlcz8_`),
			},
			want: &sources.Chunk{
				Data: []byte(`b64urlsafe-test-secret-underscores??`),
			},
		},
		{
			name: "invalid base64 string",
			chunk: &sources.Chunk{
				Data: []byte(`a3d3fa7c2bb99e469ba55e5834ce79ee4853a8a3`),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Base64{}
			got := d.FromChunk(tt.chunk)
			if tt.want != nil {
				if got == nil {
					t.Fatal("got nil, did not want nil")
				}
				if diff := pretty.Compare(string(got.Data), string(tt.want.Data)); diff != "" {
					t.Errorf("Base64FromChunk() %s diff: (-got +want)\n%s", tt.name, diff)
				}
			} else {
				if got != nil {
					t.Error("Expected nil chunk")
				}
			}
		})
	}
}

func BenchmarkFromChunkSmall(b *testing.B) {
	d := Base64{}
	data := detectors.MustGetBenchmarkData()["small"]

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		d.FromChunk(&sources.Chunk{Data: data})
	}
}

func BenchmarkFromChunkMedium(b *testing.B) {
	d := Base64{}
	data := detectors.MustGetBenchmarkData()["medium"]

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		d.FromChunk(&sources.Chunk{Data: data})
	}
}

func BenchmarkFromChunkLarge(b *testing.B) {
	d := Base64{}
	data := detectors.MustGetBenchmarkData()["large"]

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		d.FromChunk(&sources.Chunk{Data: data})
	}
}

func BenchmarkFromChunkXLarge(b *testing.B) {
	d := Base64{}
	data := detectors.MustGetBenchmarkData()["xlarge"]

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		d.FromChunk(&sources.Chunk{Data: data})
	}
}
