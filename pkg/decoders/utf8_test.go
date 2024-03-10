package decoders

import (
	"strings"
	"testing"

	"github.com/kylelemons/godebug/pretty"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestUTF8_FromChunk_ValidUTF8(t *testing.T) {
	type args struct {
		chunk *sources.Chunk
	}
	tests := []struct {
		name    string
		d       *UTF8
		args    args
		want    *sources.Chunk
		wantErr bool
	}{
		{
			name: "successful UTF8 decode",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte("plain 'ol chunk that should decode successfully")},
			},
			want:    &sources.Chunk{Data: []byte("plain 'ol chunk that should decode successfully")},
			wantErr: false,
		},
		{
			name: "empty chunk",
			d:    &UTF8{},
			args: args{
				chunk: nil,
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "valid UTF8 with control characters",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte("FIRST_KEY_123456\x00SECOND_KEY_789012")},
			},
			want:    &sources.Chunk{Data: []byte("FIRST_KEY_123456\x00SECOND_KEY_789012")},
			wantErr: false,
		},
		{
			name: "valid UTF8 with all ASCII control characters",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte{
					'S', 'T', 'A', 'R', 'T',
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
					0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
					0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
					'E', 'N', 'D',
				}},
			},
			want:    &sources.Chunk{Data: []byte("START\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1FEND")},
			wantErr: false,
		},
		{
			name: "aws key in binary data - valid utf8",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte("AWS_ACCESS_KEY_ID\x00\x00\x00AKIAEXAMPLEKEY123\x00")},
			},
			want:    &sources.Chunk{Data: []byte("AWS_ACCESS_KEY_ID\x00\x00\x00AKIAEXAMPLEKEY123\x00")},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &UTF8{}
			got := d.FromChunk(context.Background(), tt.args.chunk)
			if got != nil && tt.want != nil {
				if diff := pretty.Compare(string(got.Data), string(tt.want.Data)); diff != "" {
					t.Errorf("%s: UTF8.FromChunk() diff: (-got +want)\n%s", tt.name, diff)
				}
			} else {
				if diff := pretty.Compare(got, tt.want); diff != "" {
					t.Errorf("%s: UTF8.FromChunk() diff: (-got +want)\n%s", tt.name, diff)
				}
			}
		})
	}
}

func TestUTF8_FromChunk_InvalidUTF8(t *testing.T) {
	type args struct {
		chunk *sources.Chunk
	}
	tests := []struct {
		name    string
		d       *UTF8
		args    args
		want    *sources.Chunk
		wantErr bool
	}{
		{
			name: "basic invalid utf8",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte("\xF0\x28\x8C\x28")},
			},
			want:    &sources.Chunk{Data: []byte("�(�(")},
			wantErr: false,
		},
		{
			name: "invalid utf8 between words",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte("START\xF0\x28\x8C\x28MIDDLE\xC0\x80END")},
			},
			want:    &sources.Chunk{Data: []byte("START�(�(MIDDLE��END")},
			wantErr: false,
		},
		{
			name: "binary data with embedded text",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte{
					0xF0, 'S', 'E', 'C', 'R', 'E', 'T', // Invalid UTF-8 before text
					0xC0, 0x80, // Invalid UTF-8 sequence
					'V', 'A', 'L', 'U', 'E',
					0xFF, 0x8C, // More invalid UTF-8
				}},
			},
			want:    &sources.Chunk{Data: []byte("�SECRET��VALUE��")},
			wantErr: false,
		},
		{
			name: "binary protocol with length fields",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte{
					0x02,                   // frame type
					0x00, 0x00, 0x00, 0x0A, // length field
					'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D', '1', '2',
					0xFE, 0xFF, // checksum
				}},
			},
			want:    &sources.Chunk{Data: []byte("�����PASSWORD12��")},
			wantErr: false,
		},
		{
			name: "truncated utf8 sequence",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte("PREFIX\xF0\x28SUFFIX")},
			},
			want:    &sources.Chunk{Data: []byte("PREFIX�(SUFFIX")},
			wantErr: false,
		},
		{
			name: "multiple invalid sequences",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte{
					0xF0, 'A', // Invalid + ASCII
					0xC0, 0x80, // Invalid sequence
					'B',
					0xFF, // Single invalid byte
					'C',
					0xF0, 0x28, 0x8C, 0x28, // Invalid sequence
					'D',
				}},
			},
			want:    &sources.Chunk{Data: []byte("�A��B�C�(�(D")},
			wantErr: false,
		},
		{
			name: "invalid utf8 header with embedded secret",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte{
					0xF0, 0x28, 0x8C, // Invalid UTF-8 sequence
					'S', 'E', 'C', 'R', 'E', 'T', '=',
					0xC0, 0x80, // Another invalid UTF-8 sequence
					'A', 'K', 'I', 'A', '1', '2', '3', '4', '5', '6',
					0xF8, 0x88, // More invalid UTF-8
				}},
			},
			want:    &sources.Chunk{Data: []byte("�(�SECRET=��AKIA123456��")},
			wantErr: false,
		},
		{
			name: "key value pairs with length prefixes",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte{
					0x00, 0x01, // header
					'A', 'P', 'I', '_', 'K', 'E', 'Y', '=',
					0x00, 0x00, 0x00, 0x05, // length
					'A', 'K', 'I', 'A', '5',
					0xFF, // separator
					'S', 'E', 'C', 'R', 'E', 'T', '=',
					0x00, 0x00, 0x00, 0x06,
					'S', 'E', 'C', 'R', 'E', 'T',
				}},
			},
			want:    &sources.Chunk{Data: []byte("��API_KEY=����AKIA5�SECRET=����SECRET")},
			wantErr: false,
		},
		{
			name: "mixed binary and invalid utf8",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte{
					0x00, 0x01, // valid binary
					0xF0, 0x28, // invalid UTF-8
					'K', 'E', 'Y', '=',
					0xC0, 0x80, // more invalid UTF-8
					'V', 'A', 'L', 'U', 'E',
				}},
			},
			want:    &sources.Chunk{Data: []byte("���(KEY=��VALUE")},
			wantErr: false,
		},
		{
			name: "very large utf8 sequence",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte(strings.Repeat("世界", 1000))},
			},
			want:    &sources.Chunk{Data: []byte(strings.Repeat("世界", 1000))},
			wantErr: false,
		},
		{
			name: "single byte chunk",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte{0x41}}, // Single 'A'
			},
			want:    &sources.Chunk{Data: []byte("A")},
			wantErr: false,
		},
		{
			name: "chunk with zero bytes between valid utf8",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte("hello\x00world\x00!")},
			},
			want:    &sources.Chunk{Data: []byte("hello\x00world\x00!")},
			wantErr: false,
		},
		{
			name: "multi-byte unicode characters",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte("🌍🌎🌏")},
			},
			want:    &sources.Chunk{Data: []byte("🌍🌎🌏")},
			wantErr: false,
		},
		{
			name: "mixed ascii and multi-byte unicode with invalid sequences",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte("Hello 世界\xF0\x28\x8C\x28Testing🌍")},
			},
			want:    &sources.Chunk{Data: []byte("Hello 世界�(�(Testing🌍")},
			wantErr: false,
		},
		{
			name: "chunk ending with partial utf8 sequence",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte("Hello\xE2\x80")}, // Incomplete UTF-8 sequence
			},
			want:    &sources.Chunk{Data: []byte("Hello��")},
			wantErr: false,
		},
		{
			name: "chunk with all printable ascii chars",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte(" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~")},
			},
			want:    &sources.Chunk{Data: []byte(" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~")},
			wantErr: false,
		},
		{
			name: "alternating valid and invalid utf8",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte("A\xF0B\xF0C\xF0D")},
			},
			want:    &sources.Chunk{Data: []byte("A�B�C�D")},
			wantErr: false,
		},
		{
			name: "overlong utf8 encoding",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte{0xF0, 0x82, 0x82, 0xAC}}, // Overlong encoding of €
			},
			want:    &sources.Chunk{Data: []byte("����")},
			wantErr: false,
		},
		{
			name: "utf8 boundary conditions",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte{
					0xFF,       // Invalid single byte -> �
					0xC2, 0x80, // Minimum valid 2-byte UTF-8 sequence (U+0080) -> \u0080
					0xDF, 0xBF, // Maximum valid 2-byte UTF-8 sequence (U+07FF) -> ߿
					0xE0, 0x80, 0x80, // Invalid 3-byte (overlong encoding) -> �
					0xEF, 0xBF, 0xBF, // Valid 3-byte sequence for U+FFFF -> \uffff
					0xF0, 0x28, 0x8C, 0x28, // Invalid UTF-8 mixed with ASCII -> �(�(
					0xF4, 0x8F, 0xBF, 0xBF, // Valid 4-byte sequence for U+10FFFF -> \U0010ffff
				}},
			},
			want:    &sources.Chunk{Data: []byte("�\u0080߿���\uffff�(�(\U0010ffff")},
			wantErr: false,
		},
		{
			name: "chunk with byte order mark (BOM)",
			d:    &UTF8{},
			args: args{
				chunk: &sources.Chunk{Data: []byte{0xEF, 0xBB, 0xBF, 'h', 'e', 'l', 'l', 'o'}},
			},
			want:    &sources.Chunk{Data: []byte("\uFEFFhello")},
			wantErr: false,
		},
		{
			name: "chunk with surrogate pairs",
			d:    &UTF8{},
			args: args{
				// Invalid UTF-8 encoding of surrogate pairs
				chunk: &sources.Chunk{Data: []byte{0xED, 0xA0, 0x80, 0xED, 0xB0, 0x80}},
			},
			want:    &sources.Chunk{Data: []byte("������")},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &UTF8{}
			got := d.FromChunk(context.Background(), tt.args.chunk)
			if got != nil && tt.want != nil {
				if diff := pretty.Compare(string(got.Data), string(tt.want.Data)); diff != "" {
					t.Errorf("%s: UTF8.FromChunk() diff: (-got +want)\n%s", tt.name, diff)
				}
			} else {
				if diff := pretty.Compare(got, tt.want); diff != "" {
					t.Errorf("%s: UTF8.FromChunk() diff: (-got +want)\n%s", tt.name, diff)
				}
			}
		})
	}
}

var testBytes = []byte(`some words   with random spaces and
	
newlines with           
arbitrary length           
of

	hey

the lines themselves.

and
short
words
that
go
away.`)

func Benchmark_extractSubstrings(b *testing.B) {
	for i := 0; i < b.N; i++ {
		extractSubstrings(testBytes)
	}
}
