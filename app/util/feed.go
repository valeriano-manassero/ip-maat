package util

import (
	"time"
	"bufio"
	"bytes"
	"net/http"
	"strings"
	"regexp"
)

type IPAnalysis  struct {
	Score int
	Lists []string
}

type FeedAnalyzer  struct {
	Score int
	Expression string
}


type Feed struct {
	Name string
	Url string
	Timeout time.Duration
	FeedAnalyzers []FeedAnalyzer
}

func (feed Feed)Fetch()(map[string]IPAnalysis, error) {
	var netClient = &http.Client{
		Timeout: time.Second * feed.Timeout,
	}
	response, err := netClient.Get(feed.Url)

	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	scanner := bufio.NewScanner(response.Body)
	scanner.Split(bufio.ScanRunes)
	var buf bytes.Buffer
	for scanner.Scan() {
		buf.WriteString(scanner.Text())
	}
	var http_result= buf.String()

	result := make(map[string]IPAnalysis)
	for _, element := range strings.Split(http_result, "\n") {
		line := strings.Trim(element, " ")

		for _, fa := range feed.FeedAnalyzers {
			re := fa.Expression
			regex, _ := regexp.Compile(re)
			var findings = regex.FindStringSubmatch(line)
			if len(findings) == 2 {
				result[findings[1]] = IPAnalysis{fa.Score, []string{feed.Name}}
			}
		}
	}
	return result, nil
}