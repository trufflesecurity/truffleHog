package aws

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"google.golang.org/protobuf/types/known/structpb"
)

type scanner struct {
	skipIDs map[string]struct{}
}

func New(opts ...func(*scanner)) *scanner {
	scanner := &scanner{
		skipIDs: map[string]struct{}{},
	}
	for _, opt := range opts {

		opt(scanner)
	}

	return scanner
}

func WithSkipIDs(skipIDs []string) func(*scanner) {
	return func(s *scanner) {
		ids := map[string]struct{}{}
		for _, id := range skipIDs {
			ids[id] = struct{}{}
		}

		s.skipIDs = ids
	}
}

// Ensure the scanner satisfies the interface at compile time.
var _ detectors.Detector = (*scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	// Key types are from this list https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids
	idPat     = regexp.MustCompile(`\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b`)
	secretPat = regexp.MustCompile(`[^A-Za-z0-9+\/]{0,1}([A-Za-z0-9+\/]{40})[^A-Za-z0-9+\/]{0,1}`)
	// Hashes, like those for git, do technically match the secret pattern.
	// But they are extremely unlikely to be generated as an actual AWS secret.
	// So when we find them, if they're not verified, we should ignore the result.
	falsePositiveSecretCheck = regexp.MustCompile(`[a-f0-9]{40}`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s scanner) Keywords() []string {
	return []string{
		"AKIA",
		"ABIA",
		"ACCA",
		"ASIA",
	}
}

func GetHash(input string) string {
	data := []byte(input)
	hasher := sha256.New()
	hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil))
}

func GetHMAC(key []byte, data []byte) []byte {
	hasher := hmac.New(sha256.New, key)
	hasher.Write(data)
	return hasher.Sum(nil)
}

// FromData will find and optionally verify AWS secrets in a given set of bytes.
func (s scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, idMatch := range idMatches {
		if len(idMatch) != 2 {
			continue
		}
		resIDMatch := strings.TrimSpace(idMatch[1])

		if s.skipIDs != nil {
			if _, ok := s.skipIDs[resIDMatch]; ok {
				continue
			}
		}

		for _, secretMatch := range secretMatches {
			if len(secretMatch) != 2 {
				continue
			}
			resSecretMatch := strings.TrimSpace(secretMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AWS,
				Raw:          []byte(resIDMatch),
				Redacted:     resIDMatch,
				RawV2:        []byte(resIDMatch + resSecretMatch),
			}

			if verify {
				// REQUEST VALUES.
				method := "GET"
				service := "sts"
				host := "sts.amazonaws.com"
				region := "us-east-1"
				endpoint := "https://sts.amazonaws.com"
				datestamp := time.Now().UTC().Format("20060102")
				amzDate := time.Now().UTC().Format("20060102T150405Z0700")

				req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
				if err != nil {
					continue
				}
				req.Header.Set("Accept", "application/json")

				// TASK 1: CREATE A CANONICAL REQUEST.
				// http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
				canonicalURI := "/"
				canonicalHeaders := "host:" + host + "\n"
				signedHeaders := "host"
				algorithm := "AWS4-HMAC-SHA256"
				credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", datestamp, region, service)

				params := req.URL.Query()
				params.Add("Action", "GetCallerIdentity")
				params.Add("Version", "2011-06-15")
				params.Add("X-Amz-Algorithm", algorithm)
				params.Add("X-Amz-Credential", resIDMatch+"/"+credentialScope)
				params.Add("X-Amz-Date", amzDate)
				params.Add("X-Amz-Expires", "30")
				params.Add("X-Amz-SignedHeaders", signedHeaders)

				canonicalQuerystring := params.Encode()
				payloadHash := GetHash("") // empty payload
				canonicalRequest := method + "\n" + canonicalURI + "\n" + canonicalQuerystring + "\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash

				// TASK 2: CREATE THE STRING TO SIGN.
				stringToSign := algorithm + "\n" + amzDate + "\n" + credentialScope + "\n" + GetHash(canonicalRequest)

				// TASK 3: CALCULATE THE SIGNATURE.
				// https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
				hash := GetHMAC([]byte(fmt.Sprintf("AWS4%s", resSecretMatch)), []byte(datestamp))
				hash = GetHMAC(hash, []byte(region))
				hash = GetHMAC(hash, []byte(service))
				hash = GetHMAC(hash, []byte("aws4_request"))

				signature2 := GetHMAC(hash, []byte(stringToSign)) // Get Signature HMAC SHA256
				signature := hex.EncodeToString(signature2)

				// TASK 4: ADD SIGNING INFORMATION TO THE REQUEST.
				params.Add("X-Amz-Signature", signature)
				req.Header.Add("Content-type", "application/x-www-form-urlencoded; charset=utf-8")
				req.URL.RawQuery = params.Encode()

				res, err := client.Do(req)
				if err == nil {

					if res.StatusCode >= 200 && res.StatusCode < 300 {
						identityInfo := identityRes{}
						err := json.NewDecoder(res.Body).Decode(&identityInfo)
						if err == nil {
							s1.Verified = true
							s1.ExtraData = &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"account": structpb.NewStringValue(identityInfo.GetCallerIdentityResponse.GetCallerIdentityResult.Account),
									"user_id": structpb.NewStringValue(identityInfo.GetCallerIdentityResponse.GetCallerIdentityResult.UserID),
									"arn":     structpb.NewStringValue(identityInfo.GetCallerIdentityResponse.GetCallerIdentityResult.Arn),
								},
							}
						}
						res.Body.Close()
					} else {
						// This function will check false positives for common test words, but also it will make sure the key appears "random" enough to be a real key.
						if detectors.IsKnownFalsePositive(resSecretMatch, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}
			}

			// If the result is unverified and matches something like a git hash, don't include it in the results.
			if !s1.Verified && falsePositiveSecretCheck.MatchString(resSecretMatch) {
				continue
			}

			results = append(results, s1)
			// If we've found a verified match with this ID, we don't need to look for any more. So move on to the next ID.
			if s1.Verified {
				break
			}
		}
	}
	return awsCustomCleanResults(results), nil
}

func awsCustomCleanResults(results []detectors.Result) []detectors.Result {
	if len(results) == 0 {
		return results
	}

	// For every ID, we want at most one result, preferrably verified.
	idResults := map[string]detectors.Result{}
	for _, result := range results {
		// Always accept the verified result as the result for the given ID.
		if result.Verified {
			idResults[result.Redacted] = result
			continue
		}

		// Only include an unverified result if we don't already have a result for a given ID.
		if _, exist := idResults[result.Redacted]; !exist {
			idResults[result.Redacted] = result
		}
	}

	out := []detectors.Result{}
	for _, r := range idResults {
		out = append(out, r)
	}
	return out
}

type identityRes struct {
	GetCallerIdentityResponse struct {
		GetCallerIdentityResult struct {
			Account string `json:"Account"`
			Arn     string `json:"Arn"`
			UserID  string `json:"UserId"`
		} `json:"GetCallerIdentityResult"`
		ResponseMetadata struct {
			RequestID string `json:"RequestId"`
		} `json:"ResponseMetadata"`
	} `json:"GetCallerIdentityResponse"`
}

func (s scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AWS
}
