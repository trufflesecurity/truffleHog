package azure_storage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

var _ detectors.Detector = (*Scanner)(nil)

var (
	namePat = regexp.MustCompile(`(?i:Account[_.-]?Name|Storage[_.-]?(?:Account|Name))(?:.|\s){0,20}?\b([a-z0-9]{3,24})\b|([a-z0-9]{3,24})(?i:\.blob\.core\.windows\.net)`) // Names can only be lowercase alphanumeric.
	keyPat  = regexp.MustCompile(`(?i:(?:Access|Account|Storage)[_.-]?Key)(?:.|\s){0,25}?([a-zA-Z0-9+\/-]{86,88}={0,2})`)

	// https://learn.microsoft.com/en-us/azure/storage/common/storage-use-emulator
	testNames = map[string]struct{}{
		"devstoreaccount1": {},
		"storagesample":    {},
	}
	testKeys = map[string]struct{}{
		"Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==": {},
	}
)

func (s Scanner) Keywords() []string {
	return []string{
		"DefaultEndpointsProtocol=http", "EndpointSuffix", "core.windows.net",
		"AccountName", "Account_Name", "Account.Name", "Account-Name",
		"StorageAccount", "Storage_Account", "Storage.Account", "Storage-Account",
		"AccountKey", "Account_Key", "Account.Key", "Account-Key",
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureStorage
}

func (s Scanner) Description() string {
	return "Azure Storage is a Microsoft-managed cloud service that provides storage that is highly available, secure, durable, scalable, and redundant. Azure Storage Account keys can be used to access and manage data within storage accounts."
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Deduplicate results.
	names := make(map[string]struct{})
	for _, matches := range namePat.FindAllStringSubmatch(dataStr, -1) {
		var name string
		if matches[1] != "" {
			name = matches[1]
		} else {
			name = matches[2]
		}
		if _, ok := testNames[name]; ok {
			continue
		}
		names[name] = struct{}{}
	}
	if len(names) == 0 {
		return results, nil
	}

	keys := make(map[string]struct{})
	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		key := matches[1]
		if _, ok := testKeys[key]; ok {
			continue
		}
		keys[key] = struct{}{}
	}
	if len(keys) == 0 {
		return results, nil
	}

	// Check results.
	for name := range names {
		var s1 detectors.Result
		for key := range keys {
			s1 = detectors.Result{
				DetectorType: s.Type(),
				Raw:          []byte(key),
				RawV2:        []byte(fmt.Sprintf(`{"accountName":"%s","accountKey":"%s"}`, name, key)),
				ExtraData: map[string]string{
					"Account_name": name,
				},
			}

			if verify {
				if s.client == nil {
					s.client = detectors.GetHttpClientWithNoLocalAddresses()
				}

				isVerified, verificationErr := s.verifyMatch(ctx, s.client, name, key, s1.ExtraData)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, key)
			}

			results = append(results, s1)
			if s1.Verified {
				break
			}
		}
	}

	return results, nil
}

type storageResponse struct {
	Containers struct {
		Container []container `xml:"Container"`
	} `xml:"Containers"`
}

type container struct {
	Name string `xml:"Name"`
}

func (s Scanner) verifyMatch(ctx context.Context, client *http.Client, name string, key string, extraData map[string]string) (bool, error) {
	// https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key
	now := time.Now().UTC().Format(http.TimeFormat)
	stringToSign := "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:" + now + "\nx-ms-version:2019-12-12\n/" + name + "/\ncomp:list"
	accountKeyBytes, _ := base64.StdEncoding.DecodeString(key)
	h := hmac.New(sha256.New, accountKeyBytes)
	h.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	url := "https://" + name + ".blob.core.windows.net/?comp=list"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("x-ms-date", now)
	req.Header.Set("x-ms-version", "2019-12-12")
	req.Header.Set("Authorization", "SharedKey "+name+":"+signature)

	res, err := client.Do(req)
	if err != nil {
		// If the host is not found, we can assume that the accountName is not valid
		if strings.Contains(err.Error(), "no such host") {
			return false, nil
		}
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		// parse response
		response := storageResponse{}
		if err := xml.NewDecoder(res.Body).Decode(&response); err != nil {
			return false, err
		}

		// update the extra data with container names only
		if len(response.Containers.Container) > 0 {
			var b strings.Builder
			for i, c := range response.Containers.Container {
				if i > 0 {
					b.WriteString(", ")
				}
				b.WriteString(c.Name)
			}
			extraData["container_names"] = b.String()
		}

		return true, nil
	case http.StatusForbidden:
		// 403 if account id or key is invalid, or if the account is disabled
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}
