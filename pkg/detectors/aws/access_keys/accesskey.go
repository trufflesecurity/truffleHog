package access_keys

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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
				isVerified, extraData, verificationErr := s.verifyMatch(ctx, idMatch, secretMatch)
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

func (s scanner) verifyMatch(ctx context.Context, resIDMatch, resSecretMatch string) (bool, map[string]string, error) {
	// Prep AWS Creds for SNS
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(resIDMatch, resSecretMatch, ""),
		),
	)
	if err != nil {
		return false, nil, err
	}
	// Create STS client
	stsClient := sts.NewFromConfig(cfg)

	// Make the GetCallerIdentity API call
	resp, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		if strings.Contains(err.Error(), "StatusCode: 403") {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("request returned unexpected error: %s", err.Error())
	}

	extraData := map[string]string{
		"rotation_guide": "https://howtorotate.com/docs/tutorials/aws/",
		"account":        *resp.Account,
		"user_id":        *resp.UserId,
		"arn":            *resp.Arn,
	}
	return true, extraData, nil
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
