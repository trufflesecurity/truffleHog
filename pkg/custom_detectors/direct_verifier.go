package custom_detectors

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"golang.org/x/sync/errgroup"
)

type Target struct {
	Endpoint            string
	HeaderSet           map[string]string
	HttpMethod          string
	SuccessRanges       []string
	SuccessBodyContains []string
}

// Note: could be used to do the replacement rather than using strings
// var validatorReplaceRegex = regexp.MustCompile(`(?i)\${([a-z0-9\-]{0,})}`)

func DirectVerifyTargets(ctx context.Context, c *CustomRegexWebhook, matches []map[string][]string) []Target {
	var targets []Target
	endpoints := []string{}

	verifier := c.GetVerify()[0]
	if strings.Contains(verifier.Endpoint, "{$") {
		for _, matchSet := range matches {
			endpoint := verifier.Endpoint
			for k, v := range matchSet {
				// replace all the substitution strings with the actual values
				endpoint = strings.ReplaceAll(endpoint, "{$"+k+"}", v[0])
			}
			endpoints = append(endpoints, endpoint)
		}
	}

	// don't need duplicate endpoints per chunk
	endpoints = removeDuplicateStr(endpoints)

	headersMap := map[string][]string{}
	for _, header := range verifier.Headers {
		key, value, found := strings.Cut(header, ":")
		if found {
			headersMap[key] = append(headersMap[key], strings.TrimLeft(value, " "))
		}
	}

	// now check headers
	for headerKey, headerValue := range headersMap {
		for _, matchSet := range matches {
			for k, v := range matchSet {
				vals := headersMap[headerKey]

				// check if header exists in vals already
				skip := false
				for _, val := range vals {
					if val == strings.ReplaceAll(headerValue[0], "{$"+k+"}", v[0]) {
						skip = true
					}
				}
				if skip {
					continue
				}

				headersMap[headerKey] = append(headersMap[headerKey],
					strings.ReplaceAll(headerValue[0], "{$"+k+"}", v[0]))
			}
		}
	}

	// finally, remove the first element of each header in the headerMap since that is the substitution string
	for headerKey, headerValue := range headersMap {
		// check if the header has a substitution strings
		if strings.Contains(headerValue[0], "{$") {
			headersMap[headerKey] = headerValue[1:]
		}
	}

	headerCombinations := generateHeaderCombinations(headersMap)

	for _, endpoint := range endpoints {
		if len(headerCombinations) == 0 {
			if _, ok := c.directVerifierCache[endpoint]; ok {
				continue
			}
			c.directVerifierCache[endpoint] = true
			targets = append(targets, Target{
				Endpoint:            endpoint,
				HeaderSet:           make(map[string]string, 0),
				HttpMethod:          verifier.HttpMethod,
				SuccessRanges:       verifier.SuccessRanges,
				SuccessBodyContains: verifier.SuccessBodyContains,
			})
		}
		for _, headerSet := range headerCombinations {
			// check if we've already seen this header set and endpoint combo before
			if _, ok := c.directVerifierCache[endpoint+fmt.Sprint(headerSet)]; ok {
				continue
			}
			c.directVerifierCache[endpoint+fmt.Sprint(headerSet)] = true

			targets = append(targets, Target{
				Endpoint:            endpoint,
				HeaderSet:           headerSet,
				HttpMethod:          verifier.HttpMethod,
				SuccessRanges:       verifier.SuccessRanges,
				SuccessBodyContains: verifier.SuccessBodyContains,
			})
		}
	}
	return targets
}

func (c *CustomRegexWebhook) DirectVerify(ctx context.Context, matches []map[string][]string) ([]detectors.Result, error) {
	var results []detectors.Result

	targets := DirectVerifyTargets(ctx, c, matches)

	resultsCh := make(chan detectors.Result, maxTotalMatches)
	g := new(errgroup.Group)

	for _, target := range targets {
		target := target
		g.Go(func() error {
			// do verification
			result := detectors.Result{
				DetectorType: detectorspb.DetectorType_CustomRegex,
				DetectorName: c.GetName(),
				Raw:          []byte(target.Endpoint + fmt.Sprint(target.HeaderSet)),
				ExtraData: map[string]string{
					"name": c.GetName(),
				},
			}

			// create request
			req, err := http.NewRequestWithContext(ctx, target.HttpMethod, target.Endpoint, nil)
			if err != nil {
				return err
			}

			// add headers
			for k, v := range target.HeaderSet {
				req.Header.Add(k, v)
			}

			res, err := httpClient.Do(req)
			if err != nil {
				return err
			}

			// read response body
			body := &bytes.Buffer{}
			_, err = body.ReadFrom(res.Body)
			if err != nil {
				return err
			}

			// check if response body contains any of the success body contains
			bodyContains := false
			for _, successBodyContains := range target.SuccessBodyContains {
				if strings.Contains(body.String(), successBodyContains) {
					bodyContains = true
					break
				}
			}

			if checkStatusRanges(res.StatusCode, target.SuccessRanges) &&
				((len(target.SuccessBodyContains) > 0 && bodyContains) ||
					(len(target.SuccessBodyContains) == 0)) {
				result.Verified = true
			}
			res.Body.Close()

			// send to results channel
			resultsCh <- result

			return nil
		})
	}

	_ = g.Wait()
	close(resultsCh)
	for result := range resultsCh {
		results = append(results, result)
	}

	return results, nil
}

func checkStatusRanges(statusCode int, statusRanges []string) bool {
	statusStr := strconv.Itoa(statusCode)

	for _, statusRange := range statusRanges {
		if strings.Contains(statusRange, "x") {
			// Handle wildcard ranges
			prefix := strings.Split(statusRange, "x")[0]

			if len(prefix) == 0 { // If the prefix is empty, it's a range like "xx"
				return true
			} else if strings.HasPrefix(statusStr, prefix) {
				// Check if the status code starts with the prefix
				return true
			}
		} else {
			// Handle exact matches
			if statusStr == statusRange {
				return true
			}
		}
	}
	return false
}

func (c *CustomRegexWebhook) DirectVerifyEnabled() bool {
	// Note: dunno why this is a slice
	verifiers := c.GetVerify()
	if len(verifiers) == 0 {
		return false
	}

	verifier := verifiers[0]
	if verifier == nil {
		return false
	}
	if verifier.DirectVerify {
		return true
	}

	return false
}

// This function generates all combinations of header values
func generateHeaderCombinations(setsOfHeaders map[string][]string) []map[string]string {
	var keys []string
	for k := range setsOfHeaders {
		keys = append(keys, k)
	}

	// Start with a single empty combination
	var combinations []map[string]string
	combinations = append(combinations, make(map[string]string))

	for _, key := range keys {
		newCombinations := []map[string]string{}
		for _, oldValueMap := range combinations {
			for _, value := range setsOfHeaders[key] {
				// Copy the old combination and add a new value for the current key
				newValueMap := make(map[string]string)
				for k, v := range oldValueMap {
					newValueMap[k] = v
				}
				newValueMap[key] = value
				newCombinations = append(newCombinations, newValueMap)
			}
		}
		combinations = newCombinations
	}
	return combinations
}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
