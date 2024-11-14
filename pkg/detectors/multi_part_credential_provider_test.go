package detectors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMultiPartCredentialProviders(t *testing.T) {
	testCases := []struct {
		name         string
		provider     MultiPartCredentialProvider
		expectedSpan int64
	}{
		{
			name:         "DefaultMultiPartCredentialProvider",
			provider:     DefaultMultiPartCredentialProvider{},
			expectedSpan: defaultMaxCredentialSpan,
		},
		{
			name:         "CustomMultiPartCredentialProvider",
			provider:     NewCustomMultiPartCredentialProvider(2048),
			expectedSpan: 2048,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			span := tc.provider.MaxCredentialSpan()
			assert.Equal(t, tc.expectedSpan, span)
		})
	}
}
