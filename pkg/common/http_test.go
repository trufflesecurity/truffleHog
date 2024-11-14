package common

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"
)

func TestRetryableHTTPClientCheckRetry(t *testing.T) {
	testCases := []struct {
		name            string
		responseStatus  int
		checkRetry      retryablehttp.CheckRetry
		expectedRetries int
	}{
		{
			name:           "Retry on 500 status, give up after 3 retries",
			responseStatus: http.StatusInternalServerError, // Server error status
			checkRetry: func(ctx context.Context, resp *http.Response, err error) (bool, error) {
				if err != nil {
					t.Errorf("expected response with 500 status, got error: %v", err)
					return false, err
				}
				// The underlying transport will retry on 500 status.
				if resp.StatusCode == http.StatusInternalServerError {
					return true, nil
				}
				return false, nil
			},
			expectedRetries: 3,
		},
		{
			name:           "No retry on 400 status",
			responseStatus: http.StatusBadRequest, // Client error status
			checkRetry: func(ctx context.Context, resp *http.Response, err error) (bool, error) {
				// Do not retry on client errors.
				return false, nil
			},
			expectedRetries: 0,
		},
		{
			name:           "Retry on 429 status, give up after 3 retries",
			responseStatus: http.StatusTooManyRequests,
			checkRetry: func(ctx context.Context, resp *http.Response, err error) (bool, error) {
				if err != nil {
					t.Errorf("expected response with 429 status, got error: %v", err)
					return false, err
				}
				// The underlying transport will retry on 429 status.
				if resp.StatusCode == http.StatusTooManyRequests {
					return true, nil
				}
				return false, nil
			},
			expectedRetries: 3,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var retryCount int

			// Do not count the initial request as a retry.
			i := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if i != 0 {
					retryCount++
				}
				i++
				w.WriteHeader(tc.responseStatus)
			}))
			defer server.Close()

			ctx := context.Background()
			client := RetryableHTTPClient(WithCheckRetry(tc.checkRetry), WithTimeout(10*time.Millisecond), WithRetryWaitMin(1*time.Millisecond))
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			assert.NoError(t, err)

			// Bad linter, there is no body to close.
			_, err = client.Do(req) //nolint:bodyclose
			if slices.Contains([]int{http.StatusInternalServerError, http.StatusTooManyRequests}, tc.responseStatus) {
				// The underlying transport will retry on 500 and 429 status.
				assert.Error(t, err)
			}

			assert.Equal(t, tc.expectedRetries, retryCount, "Retry count does not match expected")
		})
	}
}

func TestRetryableHTTPClientMaxRetry(t *testing.T) {
	testCases := []struct {
		name            string
		responseStatus  int
		maxRetries      int
		expectedRetries int
	}{
		{
			name:            "Max retries with 500 status",
			responseStatus:  http.StatusInternalServerError,
			maxRetries:      2,
			expectedRetries: 2,
		},
		{
			name:            "Max retries with 429 status",
			responseStatus:  http.StatusTooManyRequests,
			maxRetries:      1,
			expectedRetries: 1,
		},
		{
			name:            "Max retries with 200 status",
			responseStatus:  http.StatusOK,
			maxRetries:      3,
			expectedRetries: 0,
		},
		{
			name:            "Max retries with 400 status",
			responseStatus:  http.StatusBadRequest,
			maxRetries:      3,
			expectedRetries: 0,
		},
		{
			name:            "Max retries with 401 status",
			responseStatus:  http.StatusUnauthorized,
			maxRetries:      3,
			expectedRetries: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var retryCount int

			i := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if i != 0 {
					retryCount++
				}
				i++
				w.WriteHeader(tc.responseStatus)
			}))
			defer server.Close()

			client := RetryableHTTPClient(
				WithMaxRetries(tc.maxRetries),
				WithTimeout(10*time.Millisecond),
				WithRetryWaitMin(1*time.Millisecond),
			)

			ctx := context.Background()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			assert.NoError(t, err)

			// Bad linter, there is no body to close.
			_, err = client.Do(req) //nolint:bodyclose
			if err != nil && tc.responseStatus == http.StatusOK {
				assert.Error(t, err)
			}

			assert.Equal(t, tc.expectedRetries, retryCount, "Retry count does not match expected")
		})
	}
}

func TestRetryableHTTPClientBackoff(t *testing.T) {
	testCases := []struct {
		name             string
		responseStatus   int
		expectedRetries  int
		backoffPolicy    retryablehttp.Backoff
		expectedBackoffs []time.Duration
	}{
		{
			name:            "Custom backoff on 500 status",
			responseStatus:  http.StatusInternalServerError,
			expectedRetries: 3,
			backoffPolicy: func(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
				switch attemptNum {
				case 1:
					return 1 * time.Millisecond
				case 2:
					return 2 * time.Millisecond
				case 3:
					return 4 * time.Millisecond
				default:
					return max
				}
			},
			expectedBackoffs: []time.Duration{1 * time.Millisecond, 2 * time.Millisecond, 4 * time.Millisecond},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var actualBackoffs []time.Duration
			var lastTime time.Time

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				now := time.Now()
				if !lastTime.IsZero() {
					actualBackoffs = append(actualBackoffs, now.Sub(lastTime))
				}
				lastTime = now
				w.WriteHeader(tc.responseStatus)
			}))
			defer server.Close()

			ctx := context.Background()
			client := RetryableHTTPClient(
				WithBackoff(tc.backoffPolicy),
				WithTimeout(10*time.Millisecond),
				WithRetryWaitMin(1*time.Millisecond),
				WithRetryWaitMax(10*time.Millisecond),
			)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			assert.NoError(t, err)

			_, err = client.Do(req) //nolint:bodyclose
			assert.Error(t, err, "Expected error due to 500 status")

			assert.Len(t, actualBackoffs, tc.expectedRetries, "Unexpected number of backoffs")

			for i, expectedBackoff := range tc.expectedBackoffs {
				if i < len(actualBackoffs) {
					// Allow some deviation in timing due to processing delays.
					assert.Less(t, math.Abs(float64(actualBackoffs[i]-expectedBackoff)), float64(15*time.Millisecond), "Unexpected backoff duration")
				}
			}
		})
	}
}
