package access_keys

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

const thinkstMessage = "This is an AWS canary token generated at canarytokens.org, and was not set off; learn more here: https://trufflesecurity.com/canaries"
const thinkstKnockoffsMessage = "This is an off brand AWS Canary inspired by canarytokens.org. It wasn't set off; learn more here: https://trufflesecurity.com/canaries"

var (
	thinkstCanaryList = map[string]struct{}{
		"052310077262": {},
		"171436882533": {},
		"534261010715": {},
		"595918472158": {},
		"717712589309": {},
		"819147034852": {},
		"992382622183": {},
		"730335385048": {},
		"266735846894": {},
	}
	thinkstKnockoffsCanaryList = map[string]struct{}{
		"044858866125": {},
		"251535659677": {},
		"344043088457": {},
		"351906852752": {},
		"390477818340": {},
		"426127672474": {},
		"427150556519": {},
		"439872796651": {},
		"445142720921": {},
		"465867158099": {},
		"637958123769": {},
		"693412236332": {},
		"732624840810": {},
		"735421457923": {},
		"959235150393": {},
		"982842642351": {},
	}
)

func (s scanner) verifyCanary(ctx context.Context, resIDMatch, resSecretMatch string) (bool, string, error) {
	// Prep AWS Creds for SNS
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(resIDMatch, resSecretMatch, ""),
		),
	)
	if err != nil {
		return false, "", err
	}
	svc := sns.NewFromConfig(cfg)

	// Prep vars and Publish to SNS
	_, err = svc.Publish(ctx, &sns.PublishInput{
		Message:     aws.String("foo"),
		PhoneNumber: aws.String("1"),
	})

	if strings.Contains(err.Error(), "not authorized to perform") {
		arn := strings.Split(err.Error(), "User: ")[1]
		arn = strings.Split(arn, " is not authorized to perform: ")[0]
		return true, arn, nil
	} else if strings.Contains(err.Error(), "does not match the signature you provided") {
		return false, "", nil
	} else if strings.Contains(err.Error(), "status code: 403") {
		return false, "", nil
	} else {
		return false, "", err
	}
}
