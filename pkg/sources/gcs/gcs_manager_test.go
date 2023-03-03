//go:build integration
// +build integration

package gcs

import (
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const (
	testProjectID = "trufflehog-testing"
	testAPIKey    = "somekeys"
	testBucket    = "test-bkt-th"
	testBucket2   = "test-bkt-th2"
	testBucket3   = "test-bkt-th3"
	testBucket4   = "test-bkt-th4"
	bucket1       = "bucket1"
	bucket2       = "bucket2"
	object1       = "object1"
	object2       = "object2"
)

func TestNewGcsManager(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name    string
		projID  string
		opts    []gcsManagerOption
		want    *gcsManager
		wantErr bool
	}{
		{
			name:   "new gcs manager, no options",
			projID: testProjectID,
			want:   &gcsManager{projectID: testProjectID, concurrency: defaultConcurrency},
		},
		{
			name:    "new gcs manager, no project id",
			projID:  "",
			wantErr: true,
		},
		{
			name:   "new gcs manager, with api key",
			projID: testProjectID,
			opts:   []gcsManagerOption{withAPIKey(ctx, testAPIKey)},
			want:   &gcsManager{projectID: testProjectID, concurrency: defaultConcurrency},
		},
		{
			name:   "new gcs manager, with json service account",
			projID: testProjectID,
			opts: []gcsManagerOption{withJSONServiceAccount(ctx, []byte(`{
				"type": "service_account",
				"project_id": "test-project"}`,
			))},
			want: &gcsManager{projectID: testProjectID, concurrency: defaultConcurrency},
		},
		{
			name:   "new gcs manager, with default ADC account",
			projID: testProjectID,
			opts:   []gcsManagerOption{withDefaultADC(ctx)},
			want:   &gcsManager{projectID: testProjectID, concurrency: defaultConcurrency},
		},
		{
			name:   "new gcs manager, with include buckets",
			projID: testProjectID,
			opts: []gcsManagerOption{
				withDefaultADC(ctx),
				withIncludeBuckets([]string{bucket1, bucket2}),
			},
			want: &gcsManager{
				projectID:      testProjectID,
				includeBuckets: map[string]struct{}{bucket1: {}, bucket2: {}},
				concurrency:    defaultConcurrency,
			},
		},
		{
			name:   "new gcs manager, with include buckets and api key",
			projID: testProjectID,
			opts:   []gcsManagerOption{withIncludeBuckets([]string{bucket1, bucket2}), withAPIKey(ctx, testAPIKey)},
			want: &gcsManager{
				projectID:      testProjectID,
				includeBuckets: map[string]struct{}{bucket1: {}, bucket2: {}},
				concurrency:    defaultConcurrency,
			},
		},
		{
			name:   "new gcs manager, with exclude buckets",
			projID: testProjectID,
			opts:   []gcsManagerOption{withExcludeBuckets([]string{bucket1, bucket2}), withAPIKey(ctx, testAPIKey)},
			want: &gcsManager{
				projectID:      testProjectID,
				excludeBuckets: map[string]struct{}{bucket1: {}, bucket2: {}},
				concurrency:    defaultConcurrency,
			},
		},
		{
			name:   "new gcs manager, with exclude buckets and api key",
			projID: testProjectID,
			opts:   []gcsManagerOption{withExcludeBuckets([]string{bucket1, bucket2}), withAPIKey(ctx, testAPIKey)},
			want: &gcsManager{
				projectID:      testProjectID,
				excludeBuckets: map[string]struct{}{bucket1: {}, bucket2: {}},
				concurrency:    defaultConcurrency,
			},
		},
		{
			name:   "new gcs manager, with include and exclude buckets",
			projID: testProjectID,
			opts: []gcsManagerOption{
				withDefaultADC(ctx),
				withIncludeBuckets([]string{bucket1, bucket2}),
				withExcludeBuckets([]string{"bucket3", "bucket4"}),
			},
			want: &gcsManager{
				projectID:      testProjectID,
				includeBuckets: map[string]struct{}{bucket1: {}, bucket2: {}},
				concurrency:    defaultConcurrency,
			},
		},
		{
			name:   "new gcs manager, with include and exclude buckets and api key",
			projID: testProjectID,
			opts: []gcsManagerOption{
				withDefaultADC(ctx),
				withIncludeBuckets([]string{bucket1, bucket2}),
				withExcludeBuckets([]string{"bucket3", "bucket4"}),
				withAPIKey(ctx, testAPIKey),
			},
			want: &gcsManager{
				projectID:      testProjectID,
				includeBuckets: map[string]struct{}{bucket1: {}, bucket2: {}},
				concurrency:    defaultConcurrency,
			},
		},
		{
			name:   "new gcs manager, with include objects, no bucket",
			projID: testProjectID,
			opts:   []gcsManagerOption{withDefaultADC(ctx), withIncludeObjects([]string{"object1", "object2"})},
			want: &gcsManager{
				projectID:      testProjectID,
				includeObjects: map[string]struct{}{object1: {}, object2: {}},
				concurrency:    defaultConcurrency,
			},
		},
		{
			name:   "new gcs manager, with include objects, include buckets",
			projID: testProjectID,
			opts: []gcsManagerOption{
				withDefaultADC(ctx),
				withIncludeObjects([]string{"object1", "object2"}),
				withIncludeBuckets([]string{bucket1, bucket2}),
			},
			want: &gcsManager{
				projectID:      testProjectID,
				includeObjects: map[string]struct{}{object1: {}, object2: {}},
				includeBuckets: map[string]struct{}{bucket1: {}, bucket2: {}},
				concurrency:    defaultConcurrency,
			},
		},
		{
			name:   "new gcs manager, with include objects and api key, include buckets",
			projID: testProjectID,
			opts: []gcsManagerOption{
				withIncludeObjects([]string{"object1", "object2"}),
				withIncludeBuckets([]string{bucket1, bucket2}),
				withAPIKey(ctx, testAPIKey),
			},
			want: &gcsManager{
				projectID:      testProjectID,
				includeObjects: map[string]struct{}{object1: {}, object2: {}},
				includeBuckets: map[string]struct{}{bucket1: {}, bucket2: {}},
				concurrency:    defaultConcurrency,
			},
		},
		{
			name:   "new gcs manager, with exclude objects",
			projID: testProjectID,
			opts:   []gcsManagerOption{withDefaultADC(ctx), withExcludeObjects([]string{"object1", "object2"})},
			want: &gcsManager{
				projectID:      testProjectID,
				excludeObjects: map[string]struct{}{object1: {}, object2: {}},
				concurrency:    defaultConcurrency,
			},
		},
		{
			name:   "new gcs manager, with exclude objects and api key",
			projID: testProjectID,
			opts:   []gcsManagerOption{withExcludeObjects([]string{"object1", "object2"}), withAPIKey(ctx, testAPIKey)},
			want: &gcsManager{
				projectID:      testProjectID,
				excludeObjects: map[string]struct{}{object1: {}, object2: {}},
				concurrency:    defaultConcurrency,
			},
		},
		{
			name:   "new gcs manager, with include and exclude objects",
			projID: testProjectID,
			opts: []gcsManagerOption{
				withDefaultADC(ctx),
				withIncludeObjects([]string{"object1", "object2"}),
				withExcludeObjects([]string{"object3", "object4"}),
			},
			want: &gcsManager{
				projectID:      testProjectID,
				includeObjects: map[string]struct{}{object1: {}, object2: {}},
				concurrency:    defaultConcurrency,
			},
		},
		{
			name:   "new gcs manager, with concurrency",
			projID: testProjectID,
			opts:   []gcsManagerOption{withDefaultADC(ctx), withConcurrency(10)},
			want: &gcsManager{
				projectID:   testProjectID,
				concurrency: 10,
			},
		},
		{
			name:   "new gcs manager, default concurrency",
			projID: testProjectID,
			opts:   []gcsManagerOption{withDefaultADC(ctx)},
			want: &gcsManager{
				projectID:   testProjectID,
				concurrency: defaultConcurrency,
			},
		},
		{
			name:   "new gcs manager, with negative concurrency",
			projID: testProjectID,
			opts:   []gcsManagerOption{withDefaultADC(ctx), withConcurrency(-1)},
			want: &gcsManager{
				projectID:   testProjectID,
				concurrency: defaultConcurrency,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newGCSManager(tc.projID, tc.opts...)
			if (err != nil) != tc.wantErr {
				t.Errorf("newGCSManager() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if err != nil {
				return
			}

			// The client should never be nil.
			if got.client == nil {
				t.Errorf("newGCSManager() client should not be nil")
			}

			if !cmp.Equal(got, tc.want, cmp.AllowUnexported(gcsManager{}), cmpopts.IgnoreFields(gcsManager{}, "client", "workerPool")) {
				t.Errorf("newGCSManager(%v, %v) got: %v, %v, want: %v, %v", tc.projID, tc.opts, got, err, tc.want, nil)
			}
		})
	}
}

func TestGCSManagerListObjects(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name       string
		projectID  string
		opts       []gcsManagerOption
		want       []object
		wantNumBkt uint32
		wantNumObj uint64
		wantErr    bool
	}{
		{
			name:      "list objects, all buckets, no objects",
			projectID: "other",
			opts:      []gcsManagerOption{withDefaultADC(ctx)},
			want:      []object{},
			wantErr:   true,
		},
		{
			name:      "list objects, all buckets, with objects",
			projectID: testProjectID,
			opts:      []gcsManagerOption{withDefaultADC(ctx)},
			want: []object{
				{
					name:        "aws1.txt",
					bucket:      testBucket,
					contentType: "text/plain",
					size:        150,
					link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th/o/aws1.txt?generation=1677870994890594&alt=media",
					acl:         []string{},
				},
				{
					name:        "moar2.txt",
					bucket:      testBucket,
					contentType: "text/plain",
					size:        12,
					link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th/o/moar2.txt?generation=1677871000378542&alt=media",
					acl:         []string{},
				},
				{
					name:        "aws3.txt",
					bucket:      testBucket2,
					contentType: "text/plain",
					size:        150,
					link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th2/o/aws3.txt?generation=1677871022489611&alt=media",
					acl:         []string{},
				},
				{
					name:        "moar.txt",
					bucket:      testBucket3,
					contentType: "text/plain",
					size:        6,
					link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th3/o/moar.txt?generation=1677871042896804&alt=media",
					acl:         []string{},
				},
				{
					name:        "AMAZON_FASHION_5.json",
					bucket:      testBucket4,
					contentType: "application/json",
					size:        1413469,
					link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th4/o/AMAZON_FASHION_5.json?generation=1677871063457469&alt=media",
					acl:         []string{},
				},
			},
			wantNumBkt: 4,
			wantNumObj: 5,
		},
		{
			name:      "list objects, include buckets, with objects",
			projectID: testProjectID,
			opts:      []gcsManagerOption{withDefaultADC(ctx), withIncludeBuckets([]string{testBucket})},
			want: []object{
				{
					name:        "aws1.txt",
					bucket:      testBucket,
					contentType: "text/plain",
					size:        150,
					link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th/o/aws1.txt?generation=1677870994890594&alt=media",
					acl:         []string{},
				},
				{
					name:        "moar2.txt",
					bucket:      testBucket,
					contentType: "text/plain",
					size:        12,
					link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th/o/moar2.txt?generation=1677871000378542&alt=media",
					acl:         []string{},
				},
			},
			wantNumBkt: 1,
			wantNumObj: 2,
		},
		{
			name:      "list objects, exclude buckets, with objects",
			projectID: testProjectID,
			opts:      []gcsManagerOption{withDefaultADC(ctx), withExcludeBuckets([]string{testBucket, testBucket2})},
			want: []object{
				{
					name:        "moar.txt",
					bucket:      testBucket3,
					contentType: "text/plain",
					size:        6,
					link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th3/o/moar.txt?generation=1677871042896804&alt=media",
					acl:         []string{},
				},
				{
					name:        "AMAZON_FASHION_5.json",
					bucket:      testBucket4,
					contentType: "application/json",
					size:        1413469,
					link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th4/o/AMAZON_FASHION_5.json?generation=1677871063457469&alt=media",
					acl:         []string{},
				},
			},
			wantNumBkt: 2,
			wantNumObj: 2,
		},
		{
			name:      "list objects, with exclude objects",
			projectID: testProjectID,
			opts:      []gcsManagerOption{withDefaultADC(ctx), withExcludeObjects([]string{"aws1.txt", "moar2.txt"})},
			want: []object{
				{
					name:        "aws3.txt",
					bucket:      testBucket2,
					contentType: "text/plain",
					size:        150,
					link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th2/o/aws3.txt?generation=1677871022489611&alt=media",
					acl:         []string{},
				},
				{
					name:        "moar.txt",
					bucket:      testBucket3,
					contentType: "text/plain",
					size:        6,
					link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th3/o/moar.txt?generation=1677871042896804&alt=media",
					acl:         []string{},
				},
				{
					name:        "AMAZON_FASHION_5.json",
					bucket:      testBucket4,
					contentType: "application/json",
					size:        1413469,
					link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th4/o/AMAZON_FASHION_5.json?generation=1677871063457469&alt=media",
					acl:         []string{},
				},
			},
			wantNumBkt: 4, // We still list objects in all buckets.
			wantNumObj: 3,
		},
		{
			name:      "list objects, with include objects, include bucket",
			projectID: testProjectID,
			opts: []gcsManagerOption{
				withDefaultADC(ctx),
				withIncludeObjects([]string{"aws1.txt"}),
				withIncludeBuckets([]string{testBucket}),
			},
			want: []object{
				{
					name:        "aws1.txt",
					bucket:      testBucket,
					contentType: "text/plain",
					size:        150,
					link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th/o/aws1.txt?generation=1677870994890594&alt=media",
					acl:         []string{},
				},
			},
			wantNumBkt: 1,
			wantNumObj: 1,
		},
		{
			name:      "list objects, with include objects",
			projectID: testProjectID,
			opts: []gcsManagerOption{
				withDefaultADC(ctx),
				withIncludeObjects([]string{"aws1.txt"}),
			},
			want: []object{
				{
					name:        "aws1.txt",
					bucket:      testBucket,
					contentType: "text/plain",
					size:        150,
					link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th/o/aws1.txt?generation=1677870994890594&alt=media",
					acl:         []string{},
				},
			},
			wantNumBkt: 4,
			wantNumObj: 1,
		},
		{
			name:      "list objects, with include bucket, exclude object",
			projectID: testProjectID,
			opts: []gcsManagerOption{
				withDefaultADC(ctx),
				withIncludeBuckets([]string{testBucket}),
				withExcludeObjects([]string{"aws1.txt"}),
			},
			want: []object{
				{
					name:        "moar2.txt",
					bucket:      testBucket,
					contentType: "text/plain",
					size:        12,
					link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th/o/moar2.txt?generation=1677871000000000&alt=media",
					acl:         []string{},
				},
			},
			wantNumBkt: 1,
			wantNumObj: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mgr, err := newGCSManager(tc.projectID, tc.opts...)
			assert.Nil(t, err)

			got, err := mgr.listObjects(ctx)
			if (err != nil) != tc.wantErr {
				t.Errorf("GCSManager.ListObjects() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			// If we expect an error, we're done.
			// Short-circuit the rest of the test.
			if err != nil {
				return
			}

			doneCh := make(chan struct{})
			defer close(doneCh)
			go func() {
				defer func() {
					doneCh <- struct{}{}
				}()
				res := make([]object, 0, len(tc.want))
				for obj := range got {
					res = append(res, obj)
				}

				if len(res) != len(tc.want) {
					t.Errorf("gcsManager.listObjects() got: %v, want: %v", res, tc.want)
				}

				// Test the bucket and object counts.
				assert.Equal(t, tc.wantNumBkt, mgr.numBuckets)
				assert.Equal(t, tc.wantNumObj, mgr.numObjects)

				// Sort the objects by name to make the test deterministic.
				// This is necessary because we list bucket objects concurrently.
				sort.Slice(res, func(i, j int) bool { return res[i].name < res[j].name })
				sort.Slice(tc.want, func(i, j int) bool { return tc.want[i].name < tc.want[j].name })

				// Test the objects are equal.
				if diff := cmp.Diff(res, tc.want, cmp.AllowUnexported(object{}), cmpopts.IgnoreFields(object{}, "reader", "createdAt", "updatedAt")); diff != "" {
					t.Errorf("gcsManager.listObjects() mismatch (-want +got):\n%s", diff)
				}
			}()

			<-doneCh
		})
	}
}
