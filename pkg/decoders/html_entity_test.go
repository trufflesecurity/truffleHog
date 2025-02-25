package decoders

import (
	"testing"

	"github.com/kylelemons/godebug/pretty"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestHtmlEntity_FromChunk(t *testing.T) {
	tests := []struct {
		name    string
		chunk   *sources.Chunk
		want    *sources.Chunk
		wantErr bool
	}{
		// &#01;
		{
			name: "[decimal] all encoded",
			chunk: &sources.Chunk{
				Data: []byte("&#116;&#111;&#107;&#101;&#110;&#58;&#32;&#34;&#103;&#104;&#112;&#95;&#73;&#119;&#100;&#77;&#120;&#57;&#87;&#70;&#87;&#82;&#82;&#102;&#77;&#104;&#84;&#89;&#105;&#97;&#86;&#106;&#90;&#55;&#56;&#74;&#102;&#117;&#97;&#109;&#118;&#110;&#48;&#89;&#87;&#82;&#77;&#48;&#34;"),
			},
			want: &sources.Chunk{
				Data: []byte("token: \"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\""),
			},
		},
		{
			name: "[decimal] mixed content",
			chunk: &sources.Chunk{
				Data: []byte(`token: "&#103;&#104;&#112;_IwdMx9WFWRRfMhTYiaVjZ78Jfuamvn0YWRM0"`),
			},
			want: &sources.Chunk{
				Data: []byte(`token: "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"`),
			},
		},
		// &#x1;
		{
			name: "[hex] all encoded",
			chunk: &sources.Chunk{
				Data: []byte("&#x74;&#x6f;&#x6b;&#x65;&#x6e;&#x3a;&#x20;&#x22;&#x67;&#x68;&#x70;&#x5f;&#x49;&#x77;&#x64;&#x4d;&#x78;&#x39;&#x57;&#x46;&#x57;&#x52;&#x52;&#x66;&#x4d;&#x68;&#x54;&#x59;&#x69;&#x61;&#x56;&#x6a;&#x5a;&#x37;&#x38;&#x4a;&#x66;&#x75;&#x61;&#x6d;&#x76;&#x6e;&#x30;&#x59;&#x57;&#x52;&#x4d;&#x30;&#x22;"),
			},
			want: &sources.Chunk{
				Data: []byte(`token: "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"`),
			},
		},
		{
			name: "[hex] mixed content",
			chunk: &sources.Chunk{
				Data: []byte(`token&colon; "ghp&UnderBar;IwdMx9WFWRRfMhTYiaVjZ78Jfuamvn0YWRM0"`),
			},
			want: &sources.Chunk{
				Data: []byte(`token: "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"`),
			},
		},
		// &quot;
		{
			name: "[named] all encoded",
			chunk: &sources.Chunk{
				Data: []byte("&Tab;&NewLine;&excl;&quot;&num;&dollar;&percnt;&amp;&apos;&lpar;&rpar;&ast;&plus;&comma;&period;&sol;&colon;&semi;&lt;&equals;&gt;&quest;&commat;&lsqb;&bsol;&rsqb;&Hat;&UnderBar;&DiacriticalGrave;&lcub;&VerticalLine;&rcub;&NonBreakingSpace;"),
			},
			want: &sources.Chunk{
				Data: []byte("\t\n!\"#$%&'()*+,./:;<=>?@[\\]^_`{|} "),
			},
		},
		{
			name: "[named] mixed content",
			chunk: &sources.Chunk{
				Data: []byte("\t&NewLine;!&quot;#&dollar;%&amp;'&lpar;)&ast;+&comma;.&sol;:&semi;<&equals;>&quest;@&lsqb;\\&rsqb;^&UnderBar;`&lcub;|&rcub;&NonBreakingSpace;"),
			},
			want: &sources.Chunk{
				Data: []byte("\t\n!\"#$%&'()*+,./:;<=>?@[\\]^_`{|} "),
			},
		},

		// nothing
		{
			name: "no escaped",
			chunk: &sources.Chunk{
				Data: []byte(`-//npm.fontawesome.com/:_authToken=12345678-2323-1111-1111-12345670B312
+//npm.fontawesome.com/:_authToken=REMOVED_TOKEN`),
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			d := &HtmlEntity{}
			got := d.FromChunk(ctx, tt.chunk)
			if tt.want != nil {
				if got == nil {
					t.Fatal("got nil, did not want nil")
				}
				if diff := pretty.Compare(string(tt.want.Data), string(got.Data)); diff != "" {
					t.Errorf("HtmlEntity.FromChunk() %s diff: (-want +got)\n%s", tt.name, diff)
				}
			} else {
				if got != nil {
					t.Error("Expected nil chunk")
				}
			}
		})
	}
}
