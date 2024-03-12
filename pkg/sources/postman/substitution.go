package postman

import (
	"fmt"
	"regexp"
	"strings"
)

var subRe = regexp.MustCompile(`\{\{[^{}]+\}\}`)

type VariableInfo struct {
	value    string
	Metadata Metadata
}

type Substitution struct {
	variables map[string][]VariableInfo
}

func NewSubstitution() *Substitution {
	return &Substitution{
		variables: make(map[string][]VariableInfo),
	}
}

func (sub *Substitution) add(metadata Metadata, key string, value string) {
	sub.variables[key] = append(sub.variables[key], VariableInfo{
		value:    value,
		Metadata: metadata,
	})
}

func (s *Source) keywordCombinations(str string) string {
	data := ""
	for _, keyword := range filterKeywords(s.keywords, s.detectorKeywords) {
		data += fmt.Sprintf("%s:%s\n", keyword, str)
	}

	return data
}

func (s *Source) buildSubstitueSet(metadata Metadata, data string) []string {
	var ret []string
	combos := make(map[string]struct{})

	s.buildSubstitution(data, metadata, &combos)

	for combo := range combos {
		ret = append(ret, s.keywordCombinations(combo))
	}

	if len(ret) == 0 {
		ret = append(ret, data)
	}
	return ret
}

func (s *Source) buildSubstitution(data string, metadata Metadata, combos *map[string]struct{}) {
	matches := removeDuplicateStr(subRe.FindAllString(data, -1))
	for _, match := range matches {
		if slices, ok := s.sub.variables[strings.Trim(match, "{}")]; ok {
			for _, slice := range slices {
				if slice.Metadata.CollectionInfo.PostmanID != "" && slice.Metadata.CollectionInfo.PostmanID != metadata.CollectionInfo.PostmanID {
					continue
				}
				d := strings.ReplaceAll(data, match, slice.value)
				s.buildSubstitution(d, metadata, combos)
			}
		}
	}

	if len(matches) == 0 {
		// add to combos
		(*combos)[data] = struct{}{}
	}
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
