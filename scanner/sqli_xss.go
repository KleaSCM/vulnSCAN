// tests attempt SQL injection and XSS by injecting basic payloads
// in the query string
package scanner

import (
	"fmt"
	"net/http"
)

func TestSQLi(url string) {
	testURL := url + "?id=1' OR '1'='1"
	resp, err := http.Get(testURL)
	if err != nil {
		fmt.Printf("Failed to test SQLi: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Println("Potential SQL Injection vulnerability found at", testURL)
	}
}

func TestXSS(url string) {
	testURL := url + "?q=<script>alert(1)</script>"
	resp, err := http.Get(testURL)
	if err != nil {
		fmt.Printf("Failed to test XSS: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Println("Potential XSS vulnerability found at", testURL)
	}
}
