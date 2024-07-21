package iobuf

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBufferedReaderSeekerRead(t *testing.T) {
	tests := []struct {
		name              string
		reader            io.Reader
		activeBuffering   bool
		reads             []int
		expectedReads     []int
		expectedBytes     [][]byte
		expectedBytesRead int64
		expectedIndex     int64
		expectedBuffer    []byte
		expectedError     error
	}{
		{
			name:              "read from seekable reader",
			reader:            strings.NewReader("test data"),
			activeBuffering:   true,
			reads:             []int{4},
			expectedReads:     []int{4},
			expectedBytes:     [][]byte{[]byte("test")},
			expectedBytesRead: 4,
			expectedIndex:     4,
		},
		{
			name:              "read from non-seekable reader with buffering",
			reader:            bytes.NewBufferString("test data"),
			activeBuffering:   true,
			reads:             []int{4},
			expectedReads:     []int{4},
			expectedBytes:     [][]byte{[]byte("test")},
			expectedBytesRead: 4,
			expectedIndex:     4,
			expectedBuffer:    []byte("test"),
		},
		{
			name:              "read from non-seekable reader without buffering",
			reader:            bytes.NewBufferString("test data"),
			activeBuffering:   false,
			reads:             []int{4},
			expectedReads:     []int{4},
			expectedBytes:     [][]byte{[]byte("test")},
			expectedBytesRead: 4,
			expectedIndex:     4,
		},
		{
			name:              "read beyond buffer",
			reader:            strings.NewReader("test data"),
			activeBuffering:   true,
			reads:             []int{10},
			expectedReads:     []int{9},
			expectedBytes:     [][]byte{[]byte("test data")},
			expectedBytesRead: 9,
			expectedIndex:     9,
		},
		{
			name:              "read with empty reader",
			reader:            strings.NewReader(""),
			activeBuffering:   true,
			reads:             []int{4},
			expectedReads:     []int{0},
			expectedBytes:     [][]byte{[]byte("")},
			expectedBytesRead: 0,
			expectedIndex:     0,
			expectedError:     io.EOF,
		},
		{
			name:              "read exact buffer size",
			reader:            strings.NewReader("test"),
			activeBuffering:   true,
			reads:             []int{4},
			expectedReads:     []int{4},
			expectedBytes:     [][]byte{[]byte("test")},
			expectedBytesRead: 4,
			expectedIndex:     4,
		},
		{
			name:              "read less than buffer size",
			reader:            strings.NewReader("te"),
			activeBuffering:   true,
			reads:             []int{4},
			expectedReads:     []int{2},
			expectedBytes:     [][]byte{[]byte("te")},
			expectedBytesRead: 2,
			expectedIndex:     2,
		},
		{
			name:              "read more than buffer size without buffering",
			reader:            bytes.NewBufferString("test data"),
			activeBuffering:   false,
			reads:             []int{4},
			expectedReads:     []int{4},
			expectedBytes:     [][]byte{[]byte("test")},
			expectedBytesRead: 4,
			expectedIndex:     4,
		},
		{
			name:              "multiple reads with buffering",
			reader:            bytes.NewBufferString("test data"),
			activeBuffering:   true,
			reads:             []int{4, 5},
			expectedReads:     []int{4, 5},
			expectedBytes:     [][]byte{[]byte("test"), []byte(" data")},
			expectedBytesRead: 9,
			expectedIndex:     9,
			expectedBuffer:    []byte("test data"),
		},
		{
			name:              "multiple reads without buffering",
			reader:            bytes.NewBufferString("test data"),
			activeBuffering:   false,
			reads:             []int{4, 5},
			expectedReads:     []int{4, 5},
			expectedBytes:     [][]byte{[]byte("test"), []byte(" data")},
			expectedBytesRead: 9,
			expectedIndex:     9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			brs := NewBufferedReadSeeker(tt.reader)
			brs.activeBuffering = tt.activeBuffering

			for i, readSize := range tt.reads {
				buf := make([]byte, readSize)
				n, err := brs.Read(buf)

				assert.Equal(t, tt.expectedReads[i], n, "read %d: unexpected number of bytes read", i+1)
				assert.Equal(t, tt.expectedBytes[i], buf[:n], "read %d: unexpected bytes", i+1)

				if i == len(tt.reads)-1 {
					if tt.expectedError != nil {
						assert.ErrorIs(t, err, tt.expectedError)
					} else {
						assert.NoError(t, err)
					}
				}
			}

			if brs.seeker == nil {
				assert.Equal(t, tt.expectedBytesRead, brs.bytesRead)
				assert.Equal(t, tt.expectedIndex, brs.index)

				if brs.buffer != nil && len(tt.expectedBuffer) > 0 {
					assert.Equal(t, tt.expectedBuffer, brs.buffer.Bytes())
				} else {
					assert.Nil(t, tt.expectedBuffer)
				}
			}
		})
	}
}

func TestBufferedReaderSeekerSeek(t *testing.T) {
	tests := []struct {
		name         string
		reader       io.Reader
		offset       int64
		whence       int
		expectedPos  int64
		expectedErr  bool
		expectedRead []byte
	}{
		{
			name:         "seek on seekable reader with SeekStart",
			reader:       strings.NewReader("test data"),
			offset:       4,
			whence:       io.SeekStart,
			expectedPos:  4,
			expectedErr:  false,
			expectedRead: []byte(" dat"),
		},
		{
			name:         "seek on seekable reader with SeekCurrent",
			reader:       strings.NewReader("test data"),
			offset:       4,
			whence:       io.SeekCurrent,
			expectedPos:  4,
			expectedErr:  false,
			expectedRead: []byte(" dat"),
		},
		{
			name:         "seek on seekable reader with SeekEnd",
			reader:       strings.NewReader("test data"),
			offset:       -4,
			whence:       io.SeekEnd,
			expectedPos:  5,
			expectedErr:  false,
			expectedRead: []byte("data"),
		},
		{
			name:         "seek on non-seekable reader with SeekStart",
			reader:       bytes.NewBufferString("test data"),
			offset:       4,
			whence:       io.SeekStart,
			expectedPos:  4,
			expectedErr:  false,
			expectedRead: []byte{},
		},
		{
			name:         "seek on non-seekable reader with SeekCurrent",
			reader:       bytes.NewBufferString("test data"),
			offset:       4,
			whence:       io.SeekCurrent,
			expectedPos:  4,
			expectedErr:  false,
			expectedRead: []byte{},
		},
		{
			name:         "seek on non-seekable reader with SeekEnd",
			reader:       bytes.NewBufferString("test data"),
			offset:       -4,
			whence:       io.SeekEnd,
			expectedPos:  5,
			expectedErr:  false,
			expectedRead: []byte{},
		},
		{
			name:         "seek to negative position",
			reader:       strings.NewReader("test data"),
			offset:       -1,
			whence:       io.SeekStart,
			expectedPos:  0,
			expectedErr:  true,
			expectedRead: nil,
		},
		{
			name:         "seek beyond EOF on non-seekable reader",
			reader:       bytes.NewBufferString("test data"),
			offset:       20,
			whence:       io.SeekEnd,
			expectedPos:  9,
			expectedErr:  false,
			expectedRead: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			brs := NewBufferedReadSeeker(tt.reader)
			pos, err := brs.Seek(tt.offset, tt.whence)
			if tt.expectedErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedPos, pos)
			if len(tt.expectedRead) > 0 {
				buf := make([]byte, len(tt.expectedRead))
				nn, err := brs.Read(buf)
				assert.NoError(t, err)
				assert.Equal(t, len(tt.expectedRead), nn)
				assert.Equal(t, tt.expectedRead, buf[:nn])
			}
		})
	}
}

func TestBufferedReaderSeekerReadAt(t *testing.T) {
	tests := []struct {
		name        string
		reader      io.Reader
		offset      int64
		length      int
		expectedN   int
		expectErr   bool
		expectedOut []byte
	}{
		{
			name:        "read within buffer on seekable reader",
			reader:      strings.NewReader("test data"),
			offset:      5,
			length:      4,
			expectedN:   4,
			expectedOut: []byte("data"),
		},
		{
			name:        "read within buffer on non-seekable reader",
			reader:      bytes.NewBufferString("test data"),
			offset:      5,
			length:      4,
			expectedN:   4,
			expectedOut: []byte("data"),
		},
		{
			name:        "read beyond buffer",
			reader:      strings.NewReader("test data"),
			offset:      9,
			length:      1,
			expectedN:   0,
			expectErr:   true,
			expectedOut: []byte{},
		},
		{
			name:        "read at start",
			reader:      strings.NewReader("test data"),
			offset:      0,
			length:      4,
			expectedN:   4,
			expectedOut: []byte("test"),
		},
		{
			name:        "read with zero length",
			reader:      strings.NewReader("test data"),
			offset:      0,
			length:      0,
			expectedN:   0,
			expectedOut: []byte{},
		},
		{
			name:        "read negative offset",
			reader:      strings.NewReader("test data"),
			offset:      -1,
			length:      4,
			expectedN:   0,
			expectErr:   true,
			expectedOut: []byte{},
		},
		{
			name:        "read beyond end on non-seekable reader",
			reader:      bytes.NewBufferString("test data"),
			offset:      20,
			length:      4,
			expectedN:   0,
			expectErr:   true,
			expectedOut: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			brs := NewBufferedReadSeeker(tt.reader)

			out := make([]byte, tt.length)
			n, err := brs.ReadAt(out, tt.offset)
			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedN, n)
			assert.Equal(t, tt.expectedOut, out[:n])
		})
	}
}

func TestBufferedReaderSeekerSize(t *testing.T) {
	tests := []struct {
		name     string
		reader   io.Reader
		expected int64
	}{
		{
			name:     "size of seekable reader",
			reader:   strings.NewReader("test data"),
			expected: 9,
		},
		{
			name:     "size of non-seekable reader",
			reader:   bytes.NewBufferString("test data"),
			expected: 9,
		},
		{
			name:     "error on non-seekable reader with partial data",
			reader:   io.LimitReader(strings.NewReader("test data"), 4),
			expected: 4,
		},
		{
			name:     "empty seekable reader",
			reader:   strings.NewReader(""),
			expected: 0,
		},
		{
			name:     "empty non-seekable reader",
			reader:   bytes.NewBufferString(""),
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			brs := NewBufferedReadSeeker(tt.reader)
			size, err := brs.Size()
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, size)
		})
	}
}

func TestBufferedReaderSeekerEnableDisableBuffering(t *testing.T) {
	tests := []struct {
		name          string
		initialState  bool
		enable        bool
		expectedState bool
	}{
		{
			name:          "enable buffering when initially disabled",
			initialState:  false,
			enable:        true,
			expectedState: true,
		},
		{
			name:          "disable buffering when initially enabled",
			initialState:  true,
			enable:        false,
			expectedState: false,
		},
		{
			name:          "enable buffering when already enabled",
			initialState:  true,
			enable:        true,
			expectedState: true,
		},
		{
			name:          "disable buffering when already disabled",
			initialState:  false,
			enable:        false,
			expectedState: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			brs := NewBufferedReadSeeker(strings.NewReader("test data"))
			brs.activeBuffering = tt.initialState

			if tt.enable {
				brs.EnableBuffering()
			} else {
				brs.DisableBuffering()
			}

			assert.Equal(t, tt.expectedState, brs.activeBuffering)
		})
	}
}
