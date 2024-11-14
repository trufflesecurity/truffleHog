//go:build detectors
// +build detectors

package github

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

func TestGitHub_FromChunk(t *testing.T) {
	t.Skip("old tokens no longer valid, and no way to generate new ones")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors2")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("GITHUB_OLD")
	secretInactive := testSecrets.MustGetField("GITHUB_OLD_INACTIVE")
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
			name: "found, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a github secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Github,
					Verified:     true,
					ExtraData: map[string]string{
						"rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
						"version":        "1",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a github secret %s within", secretInactive)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Github,
					Verified:     false,
					ExtraData: map[string]string{
						"rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
						"version":        "1",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "not found url",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("https://raw.github.com/k/d890e8640f20fba3215ba7be8e0ff145aeb8c17c/include/base64.js"),
				verify: true,
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "not found ref",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("https://github.com/lz4/lz4 @ dccf8826f1d76efcbdc655e63cc04cdbd1123619"),
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
				t.Errorf("GitHub.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatal("no raw secret present")
				}
				got[i].Raw = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("GitHub.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := Scanner{}
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
