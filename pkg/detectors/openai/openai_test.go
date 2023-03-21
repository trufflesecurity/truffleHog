//go:build detectors
// +build detectors

package openai

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestOpenAI_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors4")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	oaiUnverified := testSecrets.MustGetField("OPENAI_UNVERIFIED")
	oaiVerified := testSecrets.MustGetField("OPENAI_VERIFIED")

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}

	tests := []struct {
		name    string
		s       Scanner
		args    args
		want    []detectors.Result
		wantErr bool
	}{
		{
			name: "Found, unverified OpenAI token sk-",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find an OpenAI secret %s within", oaiUnverified)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_OpenAI,
					Redacted:     "sk-...xxxx",
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name: "Found, verified OpenAI token sk-",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find an OpenAI secret %s within", oaiVerified)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_OpenAI,
					Verified:     true,
					Redacted:     "sk-...xxxx",
				},
			},
			wantErr: false,
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{}
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("OpenAI.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatal("no raw secret present")
				}
				got[i].Raw = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("OpenAI.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := Scanner{}
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(name, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, err := s.FromData(ctx, false, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
