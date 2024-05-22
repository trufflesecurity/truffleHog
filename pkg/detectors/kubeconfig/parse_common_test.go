package kubeconfig

import (
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type testCase struct {
	name     string
	input    string
	want     []cluster
	wantErrs []error
	skip     bool
}

var errComparer = cmp.Comparer(func(x, y error) bool {
	if x == nil || y == nil {
		return x == nil && y == nil
	}

	return x.Error() == y.Error()
})

func sortClusters(clusters []cluster) {
	sort.Slice(clusters, func(i, j int) bool {
		return clusters[i].Server < clusters[j].Server
	})
}

func runTest(t *testing.T, parseFunc func(string) ([]cluster, []error), tests []testCase) {
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.skip {
				t.Skip("Skipping test: not implemented")
			}

			actual, errs := parseFunc(test.input)
			if len(errs) > 0 {
				if len(test.wantErrs) > 0 {
					if diff := cmp.Diff(test.wantErrs, errs, errComparer); diff != "" {
						t.Errorf("failed to parse config: (-want +got)\n%s", diff)
						return
					}
				} else {
					t.Errorf("got unexpected error(s): %v (%T)", errs, errs[0])
					return
				}
			}

			sortClusters(test.want)
			sortClusters(actual)
			if diff := cmp.Diff(test.want, actual); diff != "" {
				t.Errorf("diff: (-want +got)\n%s", diff)
			}
		})
	}
}
