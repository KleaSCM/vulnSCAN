package scanner

import (
	"fmt"
	"net/http"
)

// CrawlURLs performs a basic web crawl and returns discovered URLs
func CrawlURLs(url string) []string {
	var results []string
	resp, err := http.Get(url)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	// Add the main URL to results
	results = append(results, url)

	// Add common paths to check
	commonPaths := []string{
		"/",
		"/admin",
		"/login",
		"/register",
		"/api",
		"/robots.txt",
		"/sitemap.xml",
	}

	for _, path := range commonPaths {
		testURL := url + path
		resp, err := http.Get(testURL)
		if err == nil {
			results = append(results, testURL)
			resp.Body.Close()
		}
	}

	return results
}

func CheckCommonFiles(url string) {
	files := []string{
		"/.env",
		"/backup.zip",
		"/.git/",
	}

	for _, file := range files {
		checkFile(url + file)
	}
}

func checkFile(url string) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Failed to check %s: %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Printf("Potentially exposed file: %s\n", url)
	}
}
