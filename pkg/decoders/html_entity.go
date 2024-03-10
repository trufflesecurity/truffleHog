package decoders

import (
	"bytes"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/go-logr/logr"
	"golang.org/x/exp/maps"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// HtmlEntity decodes characters that are encoded as decimal, hexadecimal, or named entities.
// https://www.ee.ucl.ac.uk/~mflanaga/java/HTMLandASCIItableC1.html
type HtmlEntity struct{}

var (
	_ Decoder = (*HtmlEntity)(nil)

	once     sync.Once
	htmlTrie *ahocorasick.Trie
)

func init() {
	// Use Aho-Corasick to pre-filter potential matches.
	once.Do(func() {
		keywords := map[string]struct{}{
			`&#`:  {}, // decimal
			`&#x`: {}, // hex
		}
		for entity := range namedEntityMap {
			keywords[strings.ToLower(entity)] = struct{}{}
		}
		htmlTrie = ahocorasick.NewTrieBuilder().AddStrings(maps.Keys(keywords)).Build()
	})
}

func (d *HtmlEntity) Type() detectorspb.DecoderType {
	return detectorspb.DecoderType_HTML
}

func (d *HtmlEntity) FromChunk(ctx context.Context, chunk *sources.Chunk) *DecodableChunk {
	if chunk == nil || len(chunk.Data) == 0 {
		return nil
	} else if m := htmlTrie.MatchFirst(chunk.Data); m == nil {
		return nil
	}

	var (
		logger = ctx.Logger().WithName("decoders.html")
		// Necessary to avoid data races.
		chunkData = bytes.Clone(chunk.Data)
		matched   = false
	)
	if namedEntityPat.Match(chunkData) {
		matched = true
		chunkData = decodeNamedEntities(logger, chunkData)
	}
	if decimalEntityPat.Match(chunkData) {
		matched = true
		chunkData = decodeHtmlDecimal(logger, chunkData)
	}
	if hexEntityPat.Match(chunkData) {
		matched = true
		chunkData = decodeHtmlHex(logger, chunkData)
	}

	if matched {
		return &DecodableChunk{
			DecoderType: d.Type(),
			Chunk: &sources.Chunk{
				Data:           chunkData,
				SourceName:     chunk.SourceName,
				SourceID:       chunk.SourceID,
				JobID:          chunk.JobID,
				SecretID:       chunk.SecretID,
				SourceMetadata: chunk.SourceMetadata,
				SourceType:     chunk.SourceType,
				Verify:         chunk.Verify,
			},
		}
	} else {
		return nil
	}
}

// `A` = `&#65;`
var decimalEntityPat = regexp.MustCompile(`&#(\d{1,3});`)

func decodeHtmlDecimal(logger logr.Logger, input []byte) []byte {
	decoded := make([]byte, 0, len(input))
	lastIndex := 0

	for _, match := range decimalEntityPat.FindAllSubmatchIndex(input, -1) {
		startIndex := match[0]
		endIndex := match[1]
		decStartIndex := match[2]
		decEndIndex := match[3]

		// Copy the part of the input until the start of the entity
		decoded = append(decoded, input[lastIndex:startIndex]...)

		num, err := strconv.Atoi(string(input[decStartIndex:decEndIndex]))
		if err != nil {
			continue
		}

		// Append the decoded byte
		if num < 0 || num > 255 {
			logger.Error(errors.New("invalid decimal byte"), "Unable to decode HTML entity", "match", input[decStartIndex:decEndIndex], "byte", num)
			continue
		}
		decoded = append(decoded, byte(num))
		lastIndex = endIndex
	}

	// Append the remaining part of the input
	decoded = append(decoded, input[lastIndex:]...)

	return decoded
}

// `A` = `&#x1;`
var hexEntityPat = regexp.MustCompile(`(?i)&#x([a-f0-9]{1,2});`)

func decodeHtmlHex(logger logr.Logger, input []byte) []byte {
	decoded := make([]byte, 0, len(input))
	lastIndex := 0

	for _, match := range hexEntityPat.FindAllSubmatchIndex(input, -1) {
		startIndex := match[0]
		endIndex := match[1]
		hexStartIndex := match[2]
		hexEndIndex := match[3]

		// Copy the part of the input until the start of the entity
		decoded = append(decoded, input[lastIndex:startIndex]...)

		// Parse the hexadecimal value to an integer
		num, err := strconv.ParseInt(string(input[hexStartIndex:hexEndIndex]), 16, 32)
		if err != nil {
			continue
		}

		// Append the decoded byte
		if num < 0 || num > 255 {
			logger.Error(errors.New("invalid hex byte"), "Unable to decode HTML entity", "match", input[hexStartIndex:hexEndIndex], "byte", num)
			continue
		}
		decoded = append(decoded, byte(num))

		lastIndex = endIndex
	}

	// Append the remaining part of the input
	decoded = append(decoded, input[lastIndex:]...)

	return decoded
}

var (
	// https://www.compart.com/en/unicode/html
	namedEntityMap = map[string][]byte{
		"&tab;":              []byte("	"),
		"&newline;":          []byte("\n"),
		"&excl;":             []byte("!"),
		"&quot;":             []byte(`"`),
		"&num;":              []byte("#"),
		"&dollar;":           []byte("$"),
		"&percnt;":           []byte("%"),
		"&amp;":              []byte("&"),
		"&apos;":             []byte("'"),
		"&lpar;":             []byte("("),
		"&rpar;":             []byte(")"),
		"&ast;":              []byte("*"),
		"&plus;":             []byte("+"),
		"&comma;":            []byte(","),
		"&period;":           []byte("."),
		"&sol;":              []byte("/"),
		"&colon;":            []byte(":"),
		"&semi;":             []byte(";"),
		"&lt;":               []byte("<"),
		"&equals;":           []byte("="),
		"&gt;":               []byte(">"),
		"&quest;":            []byte("?"),
		"&commat;":           []byte("@"),
		"&lsqb;":             []byte("["),
		"&bsol;":             []byte("\\"),
		"&rsqb;":             []byte("]"),
		"&hat;":              []byte("^"),
		"&underbar;":         []byte("_"),
		"&diacriticalgrave;": []byte("`"),
		"&lcub;":             []byte("{"),
		"&verticalline;":     []byte("|"),
		"&rcub;":             []byte("}"),
		"&nonbreakingspace;": []byte(" "),
	}
	namedEntityPat = func() *regexp.Regexp {
		return regexp.MustCompile(
			"(?i)(" + strings.Join(maps.Keys(namedEntityMap), "|") + ")")
	}()
)

func decodeNamedEntities(_ logr.Logger, input []byte) []byte {
	return namedEntityPat.ReplaceAllFunc(input, func(match []byte) []byte {
		m := strings.ToLower(string(match))
		if replacement, ok := namedEntityMap[m]; ok {
			return replacement
		}
		return match
	})
}
