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
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors4")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	unverifiedGhp := testSecrets.MustGetField("GITHUB_UNVERIFIED_GHP")
	unverifiedGhpLong := testSecrets.MustGetField("GITHUB_UNVERIFIED_GHP_LONG")
	unverifiedGho := testSecrets.MustGetField("GITHUB_UNVERIFIED_GHO")
	unverifiedGhu := testSecrets.MustGetField("GITHUB_UNVERIFIED_GHU")
	unverifiedGhs := testSecrets.MustGetField("GITHUB_UNVERIFIED_GHS")
	unverifiedGhr := testSecrets.MustGetField("GITHUB_UNVERIFIED_GHR")
	verifiedGhp := testSecrets.MustGetField("GITHUB_VERIFIED_GHP")

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
			name: "found, verified ghp",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a github secret %s within", verifiedGhp)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Github,
					Verified:     true,
					ExtraData: map[string]string{
						"account_type": "User",
						// "company":        "", // not present in test verifiedGhp
						// "name":           "", // not present in test verifiedGhp
						"rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
						"scopes":         "notifications",
						// "site_admin":     "false", // not present in test verifiedGhp
						"url":      "https://github.com/truffle-sandbox",
						"username": "truffle-sandbox",
						"version":  "2",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified ghp",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a github secret %s within", unverifiedGhp)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Github,
					Verified:     false,
					ExtraData: map[string]string{
						"rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
						"version":        "2",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified gho",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a github secret %s within", unverifiedGho)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Github,
					Verified:     false,
					ExtraData: map[string]string{
						"rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
						"version":        "2",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified ghu",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a github secret %s within", unverifiedGhu)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Github,
					Verified:     false,
					ExtraData: map[string]string{
						"rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
						"version":        "2",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified ghs",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a github secret %s within", unverifiedGhs)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Github,
					Verified:     false,
					ExtraData: map[string]string{
						"rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
						"version":        "2",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified ghr",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a github secret %s within", unverifiedGhr)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Github,
					Verified:     false,
					ExtraData: map[string]string{
						"rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
						"version":        "2",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified ghp future length 255",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a github secret %s within", unverifiedGhpLong)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Github,
					Verified:     false,
					ExtraData: map[string]string{
						"rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
						"version":        "2",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("https://raw.github.com/k/d890e8640f20fba3215ba7be8e0ff145aeb8c17c/include/base64.js"),
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
