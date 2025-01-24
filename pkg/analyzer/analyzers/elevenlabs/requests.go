package elevenlabs

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
)

// permissionToAPIMap contain the API endpoints for each scope/permission
// api docs: https://elevenlabs.io/docs/api-reference/introduction
var permissionToAPIMap = map[Permission]string{
	TextToSpeech:                   "https://api.elevenlabs.io/v1/text-to-speech/%s", // require voice id
	SpeechToSpeech:                 "",
	SoundGeneration:                "",
	AudioIsolation:                 "",
	DubbingRead:                    "",
	DubbingWrite:                   "",
	ProjectsRead:                   "",
	ProjectsWrite:                  "",
	AudioNativeRead:                "",
	AudioNativeWrite:               "",
	PronunciationDictionariesRead:  "",
	PronunciationDictionariesWrite: "",
	VoicesRead:                     "",
	VoicesWrite:                    "",
	ModelsRead:                     "",
	SpeechHistoryRead:              "https://api.elevenlabs.io/v1/history",
	SpeechHistoryWrite:             "https://api.elevenlabs.io/v1/history/%s", // require history item id
	UserRead:                       "https://api.elevenlabs.io/v1/user",
	WorkspaceWrite:                 "",
}

var (
	// not exist key
	fakeID = "_thou_shalt_not_exist_"
	// error statuses
	NotVerifiable      = "api_key_not_verifiable"
	InvalidAPIKey      = "invalid_api_key"
	MissingPermissions = "missing_permissions"
)

// ErrorResponse is the error response for all APIs
type ErrorResponse struct {
	Detail struct {
		Status string `json:"status"`
	} `json:"detail"`
}

// UserResponse is the /user API response
type UserResponse struct {
	UserID       string `json:"user_id"`
	FirstName    string `json:"first_name"`
	Subscription struct {
		Tier   string `json:"tier"`
		Status string `json:"status"`
	} `json:"subscription"`
}

// HistoryResponse is the /history API response
type HistoryResponse struct {
	History []struct {
		HistoryItemID string `json:"history_item_id"`
		ModelID       string `json:"model_id"`
		VoiceID       string `json:"voice_id"`
	} `json:"history"`
}

// getAPIUrl return the API Url mapped to the permission
func getAPIUrl(permission Permission) string {
	apiUrl := permissionToAPIMap[permission]
	if strings.Contains(apiUrl, "%s") {
		return fmt.Sprintf(apiUrl, fakeID)
	}

	return apiUrl
}

// makeGetRequest send the GET request to passed url with passed key as API Key and return response body and status code
func makeGetRequest(client *http.Client, url, key string) ([]byte, int, error) {
	// create request
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}

	// add key in the header
	req.Header.Add("xi-api-key", key)

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	/*
		the reason to translate body to byte and does not directly return http.Response
		 is if we return http.Response we cannot close the body in defer. If we do we will get an error
		 when reading body outside this function
	*/
	responseBodyByte, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	return responseBodyByte, resp.StatusCode, nil
}

// getHistory get history item using the key passed and add them to secret info
func getHistory(client *http.Client, key string, secretInfo *SecretInfo) (*SecretInfo, error) {
	response, statusCode, err := makeGetRequest(client, getAPIUrl(SpeechHistoryRead), key)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusOK {
		var history HistoryResponse

		if err := json.Unmarshal(response, &history); err != nil {
			return nil, err
		}

		// add history read scope to secret info
		secretInfo.Permissions = append(secretInfo.Permissions, PermissionStrings[SpeechHistoryRead])
		// map resource to secret info
		for _, historyItem := range history.History {
			secretInfo.Resources = append(secretInfo.Resources, Resource{
				ID:         historyItem.HistoryItemID,
				Name:       "", // no name
				Type:       "History",
				Permission: PermissionStrings[SpeechHistoryRead],
			})
		}
	}

	return secretInfo, nil
}

// deleteHistory try to delete a history item. The item must not exist.
func deleteHistory(client *http.Client, key string, secretInfo *SecretInfo) (*SecretInfo, error) {
	response, statusCode, err := makeGetRequest(client, getAPIUrl(SpeechHistoryWrite), key)
	if err != nil {
		return nil, err
	}

	if statusCode >= http.StatusBadRequest && statusCode <= 499 {
		// check if status in response is not missing permissions
		ok, err := checkErrorStatus(response, MissingPermissions)
		if err != nil {
			return nil, err
		}

		// if it's missing permissions return
		if ok {
			return secretInfo, nil
		}
	}

	// add history write scope to secret info
	secretInfo.Permissions = append(secretInfo.Permissions, PermissionStrings[SpeechHistoryWrite])

	return secretInfo, nil
}

// checkErrorStatus check if any of expected error status exist in actual API error response
func checkErrorStatus(response []byte, expectedStatuses ...string) (bool, error) {
	var errorResp ErrorResponse

	if err := json.Unmarshal(response, &errorResp); err != nil {
		return false, err
	}

	if slices.Contains(expectedStatuses, errorResp.Detail.Status) {
		return true, nil
	}

	return false, nil
}
