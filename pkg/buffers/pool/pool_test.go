package pool

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/buffers/buffer"
)

func TestNewBufferPool(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		size             int
		expectedBuffSize int
	}{
		{name: "Default pool size", size: defaultBufferSize, expectedBuffSize: defaultBufferSize},
		{
			name:             "Custom pool size",
			size:             8 * 1024,
			expectedBuffSize: 8 * 1024,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pool := NewBufferPool(tc.size)
			assert.Equal(t, tc.expectedBuffSize, pool.bufferSize)
		})
	}
}

func TestBufferPoolGetPut(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name              string
		preparePool       func(p *Pool) *buffer.Buffer // Prepare the pool and return an initial buffer to put if needed
		expectedCapBefore int                          // Expected capacity before putting it back
		expectedCapAfter  int                          // Expected capacity after retrieving it again
	}{
		{
			name: "Get new buffer and put back without modification",
			preparePool: func(_ *Pool) *buffer.Buffer {
				return nil // No initial buffer to put
			},
			expectedCapBefore: defaultBufferSize,
			expectedCapAfter:  defaultBufferSize,
		},
		{
			name: "Put oversized buffer, expect shrink",
			preparePool: func(p *Pool) *buffer.Buffer {
				buf := &buffer.Buffer{Buffer: bytes.NewBuffer(make([]byte, 0, 3*defaultBufferSize))}
				return buf
			},
			expectedCapBefore: defaultBufferSize,
			expectedCapAfter:  defaultBufferSize, // Should shrink back to default
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pool := NewBufferPool(defaultBufferSize)
			initialBuf := tc.preparePool(pool)
			if initialBuf != nil {
				pool.Put(initialBuf)
			}

			buf := pool.Get()
			assert.Equal(t, tc.expectedCapBefore, buf.Cap())

			pool.Put(buf)

			bufAfter := pool.Get()
			assert.Equal(t, tc.expectedCapAfter, bufAfter.Cap())
		})
	}
}
