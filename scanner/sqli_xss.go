// tests attempt SQL injection and XSS by injecting basic payloads
// in the query string
package scanner

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// TestSQLiVulnerability tests for SQL injection vulnerabilities using multiple payloads
// and checks both response codes and error patterns in response bodies
func TestSQLiVulnerability(url string) bool {
	// SQL injection test payloads
	payloads := []string{
		"?id=1' OR '1'='1",
		"?id=1;--",
		"?id=1' AND SLEEP(5)--",
		"?id=1' UNION SELECT NULL--",
	}

	// Common SQL error patterns
	errorPatterns := []string{
		"sql syntax",
		"mysql",
		"sqlite",
		"postgresql",
		"oracle",
		"syntax error",
		"unclosed quotation",
		"unterminated string",
		"warning: mysql",
		"database error",
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	for _, payload := range payloads {
		testURL := url + payload
		start := time.Now()
		resp, err := client.Get(testURL)
		elapsed := time.Since(start)

		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		bodyStr := strings.ToLower(string(body))

		// Check for SQL error patterns in response
		for _, pattern := range errorPatterns {
			if strings.Contains(bodyStr, pattern) {
				return true
			}
		}

		// Check for time-based injection success
		if strings.Contains(payload, "SLEEP") && elapsed.Seconds() > 4 {
			return true
		}

		// Check for suspicious response codes
		if resp.StatusCode == 500 || resp.StatusCode == 200 {
			// Additional check for union-based injection
			if strings.Contains(payload, "UNION") && len(body) > 0 {
				return true
			}
		}
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
