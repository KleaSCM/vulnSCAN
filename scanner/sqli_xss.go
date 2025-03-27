// tests attempt SQL injection and XSS by injecting basic payloads
// in the query string
package scanner

import (
	"fmt"
	"net/http"
)

// TestSQLiVulnerability tests for SQL injection vulnerabilities by appending a malicious
// SQL injection payload ('OR '1'='1) to the URL's query string. If the server responds
// with a 200 OK status code when this payload is injected, it may indicate that the
// application is vulnerable to SQL injection attacks since it appears to be processing
// the malicious input without proper sanitization.
func TestSQLiVulnerability(url string) bool {
	testURL := url + "?id=1' OR '1'='1"
	resp, err := http.Get(testURL)
	if err != nil {
		fmt.Printf("Failed to test SQLi: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Println("Potential SQL Injection vulnerability found at", testURL)
		return true
	}
	return false
}

// TestXSSVulnerability tests for XSS (Cross-Site Scripting) vulnerabilities by appending a basic
// XSS payload (<script>alert(1)</script>) to the URL's query string. If the server responds with
// a 200 OK status code when this payload is injected, it may indicate that the application is
// vulnerable to XSS attacks since it appears to be accepting and potentially rendering the
// malicious JavaScript without proper sanitization.
func TestXSSVulnerability(url string) bool {
	testURL := url + "?q=<script>alert(1)</script>"
	resp, err := http.Get(testURL)
	if err != nil {
		fmt.Printf("Failed to test XSS: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Println("Potential XSS vulnerability found at", testURL)
		return true
	}
	return false
}
