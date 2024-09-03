//go:build detectors
// +build detectors

package robinhoodcrypto

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestRobinhoodCrypto_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "typical pattern",
			input: `
				api_key = "rh-api-e3bb245e-a45c-4729-8a9b-10201756f8cc"
				private_key_base64 = "aVhXn8ghC9YqSz5RyFuKc6SsDC6SuPIqSW3IXH76ZlMCjOxkazBQjQFucJLk3uNorpBt6TbYpo/D1lHA7s4+hQ=="
			`,
			want: []string{
				"rh-api-e3bb245e-a45c-4729-8a9b-10201756f8cc" +
					"aVhXn8ghC9YqSz5RyFuKc6SsDC6SuPIqSW3IXH76ZlMCjOxkazBQjQFucJLk3uNorpBt6TbYpo/D1lHA7s4+hQ==",
			},
		},
	}

	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
				if len(matchedDetectors) == 0 {
					t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
					return
				}

				results, err := d.FromData(context.Background(), false, []byte(test.input))
				if err != nil {
					t.Errorf("error = %v", err)
					return
				}

				if len(results) != len(test.want) {
					if len(results) == 0 {
						t.Errorf("did not receive result")
					} else {
						t.Errorf("expected %d results, only received %d", len(test.want), len(results))
					}
					return
				}

				actual := make(map[string]struct{}, len(results))
				for _, r := range results {
					if len(r.RawV2) > 0 {
						actual[string(r.RawV2)] = struct{}{}
					} else {
						actual[string(r.Raw)] = struct{}{}
					}
				}
				expected := make(map[string]struct{}, len(test.want))
				for _, v := range test.want {
					expected[v] = struct{}{}
				}

				if diff := cmp.Diff(expected, actual); diff != "" {
					t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
				}
			},
		)
	}
}

func TestRobinhoodcrypto_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	// Valid and active credentials.
	apiKey := testSecrets.MustGetField("ROBINHOODCRYPTO_APIKEY")
	privateKey := testSecrets.MustGetField("ROBINHOODCRYPTO_PRIVATEKEY")

	// Valid but inactive credentials.
	inactiveApiKey := testSecrets.MustGetField("ROBINHOODCRYPTO_APIKEY_INACTIVE")
	inactivePrivateKey := testSecrets.MustGetField("ROBINHOODCRYPTO_PRIVATEKEY_INACTIVE")

	// Invalid credentials.
	deletedApiKey := testSecrets.MustGetField("ROBINHOODCRYPTO_APIKEY_DELETED")
	deletedPrivateKey := testSecrets.MustGetField("ROBINHOODCRYPTO_PRIVATEKEY_DELETED")

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name                string
		s                   Scanner
		args                args
		want                []detectors.Result
		wantErr             bool
		wantVerificationErr bool
	}{
		{
			name: "found, verified",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(
					"You can find a robinhoodcrypto api key %s and a private key %s within", apiKey, privateKey,
				)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_RobinhoodCrypto,
					Verified:     true,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, verified, but inactive",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(
					"You can find a robinhoodcrypto api key %s and a private key %s within", inactiveApiKey,
					inactivePrivateKey,
				)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_RobinhoodCrypto,
					Verified:     true,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(
					"You can find a robinhoodcrypto api key %s and a private key %s within", deletedApiKey,
					deletedPrivateKey,
				)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_RobinhoodCrypto,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			want:                nil,
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, would be verified if not for timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(
					"You can find a robinhoodcrypto api key %s and a private key %s within", apiKey, privateKey,
				)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_RobinhoodCrypto,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "found, verified but unexpected api surface",
			s:    Scanner{client: common.ConstantResponseHttpClient(404, "")},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(
					"You can find a robinhoodcrypto api key %s and a private key %s within", apiKey, privateKey,
				)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_RobinhoodCrypto,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
				if (err != nil) != tt.wantErr {
					t.Errorf("Robinhoodcrypto.FromData() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				for i := range got {
					if len(got[i].Raw) == 0 {
						t.Fatalf("no raw secret present: \n %+v", got[i])
					}
					if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
						t.Fatalf(
							"wantVerificationError = %v, verification error = %v", tt.wantVerificationErr,
							got[i].VerificationError(),
						)
					}
				}
				ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "ExtraData", "Raw", "RawV2", "verificationError")
				if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
					t.Errorf("Robinhoodcrypto.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
				}
			},
		)
	}
}

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := Scanner{}
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(
			name, func(b *testing.B) {
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					_, err := s.FromData(ctx, false, data)
					if err != nil {
						b.Fatal(err)
					}
				}
			},
		)
	}
}
