package shopify

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestShopify_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors4")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("SHOPIFY_ADMIN_SECRET")
	inactiveSecret := testSecrets.MustGetField("SHOPIFY_ADMIN_SECRET_INACTIVE")
	domain := testSecrets.MustGetField("SHOPIFY_DOMAIN")

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
				data:   []byte(fmt.Sprintf("You can find a shopify secret %s domain https://%s", secret, domain)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Shopify,
					Redacted:     domain,
					Verified:     true,
					ExtraData: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"access_scopes": structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{
								structpb.NewStringValue("read_analytics"),
								structpb.NewStringValue("unauthenticated_read_selling_plans"),
							}}),
						},
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
				data:   []byte(fmt.Sprintf("You can find a shopify secret %s within (domain https://%s) but not valid", inactiveSecret, domain)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Shopify,
					Redacted:     domain,
					Verified:     false,
					ExtraData:    nil,
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
				t.Errorf("Shopify.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if tt.want[i].ExtraData != nil {
					if !proto.Equal(got[i].ExtraData, tt.want[i].ExtraData) {
						t.Errorf("AWS.FromData() %s extra data not equal: got %+v, want %+v", tt.name, got[i].ExtraData, tt.want[i].ExtraData)
					}
				}
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				got[i].Raw = nil
			}
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "RawV2", "Raw", "ExtraData")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("AWS.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
