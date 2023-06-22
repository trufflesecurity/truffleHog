package common

import (
	"regexp"
	"testing"
)

const (
	usernamePattern = `?()/\+=\s\n`
	passwordPattern = `^<>;.*&|£\n\s`
	usernameRegex   = `(?im)(?:user|usr)\S{0,40}?[:=\s]{1,3}[ '"=]{0,1}([^:?()/\+=\s\n]{4,40})\b`
	passwordRegex   = `(?im)(?:pass|password)\S{0,40}?[:=\s]{1,3}[ '"=]{0,1}([^:^<>;.*&|£\n\s]{4,40})`
)

func TestUsernameRegexCheck(t *testing.T) {
	usernameRegexPat := UsernameRegexCheck(usernamePattern)

	expectedRegexPattern := regexp.MustCompile(usernameRegex)

	if usernameRegexPat.compiledRegex.String() != expectedRegexPattern.String() {
		t.Errorf("\n got %v \n want %v", usernameRegexPat.compiledRegex, expectedRegexPattern)
	}

	testString := `username = "johnsmith123"
                   username='johnsmith123'
				   username:="johnsmith123"
                   username = johnsmith123
                   username=johnsmith123`

	expectedStr := []string{"johnsmith123", "johnsmith123", "johnsmith123", "johnsmith123", "johnsmith123"}

	usernameRegexMatches := usernameRegexPat.Matches([]byte(testString))

	if len(usernameRegexMatches) != len(expectedStr) {
		t.Errorf("\n got %v \n want %v", usernameRegexMatches, expectedStr)
	}

}

func TestPasswordRegexCheck(t *testing.T) {
	passwordRegexPat := PasswordRegexCheck(passwordPattern)

	expectedRegexPattern := regexp.MustCompile(passwordRegex)

	if passwordRegexPat.compiledRegex.String() != expectedRegexPattern.String() {
		t.Errorf("\n got  %v \n want %v", passwordRegexPat.compiledRegex, expectedRegexPattern)
	}

	testString := `password = "johnsmith123$!"
                   password='johnsmith123$!'
				   password:="johnsmith123$!"
                   password = johnsmith123$!
                   password=johnsmith123$!
				   PasswordAuthenticator(username, "johnsmith123$!")`

	expectedStr := []string{"johnsmith123$!", "johnsmith123$!", "johnsmith123$!", "johnsmith123$!", "johnsmith123$!",
		"johnsmith123$!"}

	passwordRegexMatches := passwordRegexPat.Matches([]byte(testString))

	if len(passwordRegexMatches) != len(expectedStr) {
		t.Errorf("\n got %v \n want %v", passwordRegexMatches, expectedStr)
	}

}
