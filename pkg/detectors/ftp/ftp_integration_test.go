//go:build detectors
// +build detectors

package ftp

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestFTP_FromChunk(t *testing.T) {
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
			name: "bad scheme",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("file://user:pass@foo.com:123/wh/at/ever"),
				verify: true,
			},
			wantErr: false,
		},
		{
			name: "verified FTP",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				// https://dlptest.com/ftp-test/
				data:   []byte("ftp://dlpuser:rNrKYTX9g7z3RgJRmxWuGHbeu@ftp.dlptest.com"),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_FTP,
					Verified:     true,
					Redacted:     "ftp://dlpuser:********@ftp.dlptest.com",
				},
			},
			wantErr: false,
		},
		{
			name: "unverified FTP",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				// https://dlptest.com/ftp-test/
				data:   []byte("ftp://dlpuser:invalid@ftp.dlptest.com"),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_FTP,
					Verified:     false,
					Redacted:     "ftp://dlpuser:********@ftp.dlptest.com",
				},
			},
			wantErr: false,
		},
		{
			name: "bad host",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				// https://dlptest.com/ftp-test/
				data:   []byte("ftp://dlpuser:rNrKYTX9g7z3RgJRmxWuGHbeu@ftp.dlptest.com.badhost"),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_FTP,
					Verified:     false,
					Redacted:     "ftp://dlpuser:********@ftp.dlptest.com.badhost",
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "timeout",
			s:    Scanner{verificationTimeout: 1 * time.Microsecond},
			args: args{
				ctx: context.Background(),
				// https://dlptest.com/ftp-test/
				data:   []byte("ftp://dlpuser:rNrKYTX9g7z3RgJRmxWuGHbeu@ftp.dlptest.com"),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_FTP,
					Verified:     false,
					Redacted:     "ftp://dlpuser:********@ftp.dlptest.com",
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "blocked FP",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("ftp://abc:123@ftp.freebsd.org/pub/FreeBSD/doc/tr/articles/explaining-bsd/explaining-bsd_tr.pdf"),
				verify: true,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("URI.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// if os.Getenv("FORCE_PASS_DIFF") == "true" {
			// 	return
			// }
			for i := range got {
				got[i].Raw = nil

				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Fatalf("wantVerificationError = %v, verification error = %v", tt.wantVerificationErr, got[i].VerificationError())
				}
			}
			opts := cmpopts.IgnoreFields(detectors.Result{}, "verificationError")
			if diff := cmp.Diff(got, tt.want, opts); diff != "" {
				t.Errorf("FTP.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
