package access_keys

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/aws"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type scanner struct {
	verificationClient *http.Client
	skipIDs            map[string]struct{}
	detectors.DefaultMultiPartCredentialProvider
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
var _ interface {
	detectors.Detector
	detectors.CustomResultsCleaner
	detectors.MultiPartCredentialProvider
} = (*scanner)(nil)

var (
	defaultVerificationClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	// Key types are from this list https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids
	idPat = regexp.MustCompile(`\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s scanner) Keywords() []string {
	return []string{
		"AKIA",
		"ABIA",
		"ACCA",
	}
}

// FromData will find and optionally verify AWS secrets in a given set of bytes.
func (s scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	logger := logContext.AddLogger(ctx).Logger().WithName("aws")
	dataStr := string(data)
	dataStr = aws.UrlEncodedReplacer.Replace(dataStr)

	// Filter & deduplicate matches.
	idMatches := make(map[string]struct{})
	for _, matches := range idPat.FindAllStringSubmatch(dataStr, -1) {
		idMatches[matches[1]] = struct{}{}
	}
	secretMatches := make(map[string]struct{})
	for _, matches := range aws.SecretPat.FindAllStringSubmatch(dataStr, -1) {
		secretMatches[matches[1]] = struct{}{}
	}

	// Process matches.
	for idMatch := range idMatches {
		if detectors.StringShannonEntropy(idMatch) < aws.RequiredIdEntropy {
			continue
		}
		if s.skipIDs != nil {
			if _, ok := s.skipIDs[idMatch]; ok {
				continue
			}
		}

		for secretMatch := range secretMatches {
			if detectors.StringShannonEntropy(secretMatch) < aws.RequiredSecretEntropy {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AWS,
				Raw:          []byte(idMatch),
				Redacted:     idMatch,
				RawV2:        []byte(idMatch + ":" + secretMatch),
				ExtraData: map[string]string{
					"resource_type": aws.ResourceTypes[idMatch[:4]],
				},
			}

			// Decode the account ID.
			account, err := aws.GetAccountNumFromID(idMatch)
			isCanary := false
			if err != nil {
				logger.V(3).Info("Failed to decode account number", "err", err)
			} else {
				s1.ExtraData["account"] = account

				// Handle canary IDs.
				if _, ok := thinkstCanaryList[account]; ok {
					isCanary = true
					s1.ExtraData["message"] = thinkstMessage
					if verify {
						verified, arn, err := s.verifyCanary(ctx, idMatch, secretMatch)
						s1.Verified = verified
						if arn != "" {
							s1.ExtraData["arn"] = arn
						}
						s1.SetVerificationError(err, secretMatch)
					}
				}
				if _, ok := thinkstKnockoffsCanaryList[account]; ok {
					isCanary = true
					s1.ExtraData["message"] = thinkstKnockoffsMessage
					if verify {
						verified, arn, err := s.verifyCanary(ctx, idMatch, secretMatch)
						s1.Verified = verified
						if arn != "" {
							s1.ExtraData["arn"] = arn
						}
						s1.SetVerificationError(err, secretMatch)
					}
				}

				if isCanary {
					s1.ExtraData["is_canary"] = "true"
				}
			}

			if verify && !isCanary {
				isVerified, extraData, verificationErr := s.verifyMatch(ctx, idMatch, secretMatch, true)
				s1.Verified = isVerified

				// Log if the calculated ID does not match the ID value from verification.
				// Should only be edge cases at most.
				if account != "" && extraData["account"] != "" && extraData["account"] != s1.ExtraData["account"] {
					logger.V(2).Info("Calculated account ID does not match actual account ID", "calculated", account, "actual", extraData["account"])
				}

				// Append the extraData to the existing ExtraData map.
				for k, v := range extraData {
					s1.ExtraData[k] = v
				}
				s1.SetVerificationError(verificationErr, secretMatch)
			}

			if !s1.Verified && aws.FalsePositiveSecretPat.MatchString(secretMatch) {
				// Unverified results that look like hashes are probably not secrets
				continue
			}

			results = append(results, s1)
			// If we've found a verified match with this ID, we don't need to look for any more. So move on to the next ID.
			if s1.Verified {
				delete(secretMatches, secretMatch)
				break
			}
		}
	}
	return results, nil
}

func (s scanner) ShouldCleanResultsIrrespectiveOfConfiguration() bool {
	return true
}

const (
	method   = "GET"
	service  = "sts"
	host     = "sts.amazonaws.com"
	region   = "us-east-1"
	endpoint = "https://sts.amazonaws.com"
)

func (s scanner) verifyMatch(ctx context.Context, resIDMatch, resSecretMatch string, retryOn403 bool) (bool, map[string]string, error) {
	// REQUEST VALUES.
	now := time.Now().UTC()
	datestamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z0700")

	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return false, nil, err
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
	payloadHash := aws.GetHash("") // empty payload
	canonicalRequest := method + "\n" + canonicalURI + "\n" + canonicalQuerystring + "\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash

	// TASK 2: CREATE THE STRING TO SIGN.
	stringToSign := algorithm + "\n" + amzDate + "\n" + credentialScope + "\n" + aws.GetHash(canonicalRequest)

	// TASK 3: CALCULATE THE SIGNATURE.
	// https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
	hash := aws.GetHMAC([]byte(fmt.Sprintf("AWS4%s", resSecretMatch)), []byte(datestamp))
	hash = aws.GetHMAC(hash, []byte(region))
	hash = aws.GetHMAC(hash, []byte(service))
	hash = aws.GetHMAC(hash, []byte("aws4_request"))

	signature2 := aws.GetHMAC(hash, []byte(stringToSign)) // Get Signature HMAC SHA256
	signature := hex.EncodeToString(signature2)

	// TASK 4: ADD SIGNING INFORMATION TO THE REQUEST.
	params.Add("X-Amz-Signature", signature)
	req.Header.Add("Content-type", "application/x-www-form-urlencoded; charset=utf-8")
	req.URL.RawQuery = params.Encode()

	client := s.verificationClient
	if client == nil {
		client = defaultVerificationClient
	}

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	// TODO: tighten range of acceptable status codes
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		identityInfo := aws.IdentityResponse{}
		if err := json.NewDecoder(res.Body).Decode(&identityInfo); err != nil {
			return false, nil, err
		}

		extraData := map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/aws/",
			"account":        identityInfo.GetCallerIdentityResponse.GetCallerIdentityResult.Account,
			"user_id":        identityInfo.GetCallerIdentityResponse.GetCallerIdentityResult.UserID,
			"arn":            identityInfo.GetCallerIdentityResponse.GetCallerIdentityResult.Arn,
		}
		return true, extraData, nil
	} else if res.StatusCode == 403 {
		// Experimentation has indicated that if you make two GetCallerIdentity requests within five seconds that
		// share a key ID but are signed with different secrets the second one will be rejected with a 403 that
		// carries a SignatureDoesNotMatch code in its body. This happens even if the second ID-secret pair is
		// valid. Since this is exactly our access pattern, we need to work around it.
		//
		// Fortunately, experimentation has also revealed a workaround: simply resubmit the second request. The
		// response to the resubmission will be as expected. But there's a caveat: You can't have closed the body of
		// the response to the original second request, or read to its end, or the resubmission will also yield a
		// SignatureDoesNotMatch. For this reason, we have to re-request all 403s. We can't re-request only
		// SignatureDoesNotMatch responses, because we can only tell whether a given 403 is a SignatureDoesNotMatch
		// after decoding its response body, which requires reading the entire response body, which disables the
		// workaround.
		//
		// We are clearly deep in the guts of AWS implementation details here, so this all might change with no
		// notice. If you're here because something in this detector broke, you have my condolences.
		if retryOn403 {
			return s.verifyMatch(ctx, resIDMatch, resSecretMatch, false)
		}

		var body aws.ErrorResponseBody
		if err = json.NewDecoder(res.Body).Decode(&body); err != nil {
			return false, nil, fmt.Errorf("couldn't parse the sts response body (%v)", err)
		}
		// All instances of the code I've seen in the wild are PascalCased but this check is
		// case-insensitive out of an abundance of caution
		if strings.EqualFold(body.Error.Code, "InvalidClientTokenId") {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("request returned status %d with an unexpected reason (%s: %s)", res.StatusCode, body.Error.Code, body.Error.Message)
	} else {
		return false, nil, fmt.Errorf("request to %v returned unexpected status %d", res.Request.URL, res.StatusCode)
	}
}

func (s scanner) CleanResults(results []detectors.Result) []detectors.Result {
	return aws.CleanResults(results)
}

func (s scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AWS
}

func (s scanner) Description() string {
	return "AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached."
}
