//go:build detectors
// +build detectors

package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

var postgresDockerHash string

const (
	postgresUser = "postgres"
	postgresPass = "23201dabb56ca236f3dc6736c0f9afad"
	postgresHost = "localhost"
	postgresPort = "5434" // Do not use 5433, as local dev environments can use it for other things

	inactiveUser = "inactive"
	inactivePass = "inactive"
	inactivePort = "61000"
	inactiveHost = "192.0.2.0"
)

func TestPostgres_FromChunk(t *testing.T) {
	if err := startPostgres(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Fatalf("could not start local postgres: %v w/stderr:\n%s", err, string(exitErr.Stderr))
		} else {
			t.Fatalf("could not start local postgres: %v", err)
		}
	}
	defer stopPostgres()

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
		{
			name: "found connection URI, verified",
			s:    Scanner{detectLoopback: true},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf(`postgresql://%s:%s@%s:%s/postgres`, postgresUser, postgresPass, postgresHost, postgresPort)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Postgres,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "found connection URI, unverified",
			s:    Scanner{detectLoopback: true},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf(`postgresql://%s:%s@%s:%s/postgres`, postgresUser, inactivePass, postgresHost, postgresPort)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Postgres,
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name: "ignored localhost",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf(`postgresql://%s:%s@%s:%s/postgres`, postgresUser, postgresPass, "localhost", postgresPort)),
				verify: true,
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "ignored 127.0.0.1",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf(`postgresql://%s:%s@%s:%s/postgres`, postgresUser, postgresPass, "127.0.0.1", postgresPort)),
				verify: true,
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "found connection URI, unverified due to error - inactive host",
			s:    Scanner{},
			args: func() args {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				return args{
					ctx:    ctx,
					data:   []byte(fmt.Sprintf(`postgresql://%s:%s@%s:%s/postgres`, postgresUser, postgresPass, inactiveHost, postgresPort)),
					verify: true,
				}
			}(),
			want: func() []detectors.Result {
				r := detectors.Result{
					DetectorType: detectorspb.DetectorType_Postgres,
					Verified:     false,
				}
				r.SetVerificationError(errors.New("i/o timeout"))
				return []detectors.Result{r}
			}(),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("postgres.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				gotErr := ""
				if got[i].VerificationError() != nil {
					gotErr = got[i].VerificationError().Error()
				}
				wantErr := ""
				if tt.want[i].VerificationError() != nil {
					wantErr = tt.want[i].VerificationError().Error()
				}
				if gotErr != wantErr {
					t.Fatalf("wantVerificationError = %v, verification error = %v", tt.want[i].VerificationError(), got[i].VerificationError())
				}
			}
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "RawV2", "verificationError")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("Postgres.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func dockerLogLine(hash string, needle string) chan struct{} {
	ch := make(chan struct{}, 1)
	go func() {
		for {
			out, err := exec.Command("docker", "logs", hash).CombinedOutput()
			if err != nil {
				panic(err)
			}
			if strings.Contains(string(out), needle) {
				ch <- struct{}{}
				return
			}
			time.Sleep(1 * time.Second)
		}
	}()
	return ch
}

func startPostgres() error {
	cmd := exec.Command(
		"docker", "run", "--rm", "-p", postgresPort+":"+defaultPort,
		"-e", "POSTGRES_PASSWORD="+postgresPass,
		"-e", "POSTGRES_USER="+postgresUser,
		"-d", "postgres",
	)
	fmt.Println(cmd.String())
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	postgresDockerHash = string(bytes.TrimSpace(out))
	select {
	case <-dockerLogLine(postgresDockerHash, "PostgreSQL init process complete; ready for start up."):
		return nil
	case <-time.After(30 * time.Second):
		stopPostgres()
		return errors.New("timeout waiting for postgres database to be ready")
	}
}

func stopPostgres() {
	exec.Command("docker", "kill", postgresDockerHash).Run()
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
