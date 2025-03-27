// Package scanner provides security scanning capabilities for web applications
package scanner

import (
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"time"
)

// TestSQLiVulnerability performs SQL injection testing using multiple techniques:
// 1. Boolean-based injection: Tests for SQL syntax errors and unexpected responses
// 2. Time-based injection: Detects delays in response times
// 3. Union-based injection: Checks for successful UNION queries
// 4. Error-based injection: Looks for SQL error messages in responses
//
// The function returns true if any SQL injection vulnerability is detected.
func TestSQLiVulnerability(url string) bool {
	// SQL injection test payloads targeting different injection techniques
	payloads := []string{
		"?id=1' OR '1'='1",           // Boolean-based injection
		"?id=1;--",                   // Comment-based injection
		"?id=1' AND SLEEP(5)--",      // Time-based injection
		"?id=1' UNION SELECT NULL--", // Union-based injection
	}

	// Common SQL error patterns that indicate a vulnerability
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

	// Configure HTTP client with timeout to prevent hanging
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Test each payload and analyze responses
	for _, payload := range payloads {
		testURL := url + payload
		start := time.Now()
		resp, err := client.Get(testURL)
		elapsed := time.Since(start)

		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Read and analyze response body
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

		// Check for suspicious response codes and union-based injection
		if resp.StatusCode == 500 || resp.StatusCode == 200 {
			if strings.Contains(payload, "UNION") && len(body) > 0 {
				return true
			}
		}
	}

	return false
}

// TestXSSVulnerability performs Cross-Site Scripting (XSS) testing using multiple techniques:
// 1. Script tag injection: Tests for basic script execution
// 2. Event handler injection: Tests for event-based XSS
// 3. JavaScript protocol injection: Tests for URL-based XSS
// 4. DOM-based injection: Tests for DOM manipulation
//
// The function returns true if any XSS vulnerability is detected.
func TestXSSVulnerability(url string) bool {
	// XSS test payloads targeting different injection contexts
	payloads := []string{
		"<script>alert(1)</script>",                 // Basic script injection
		"\"><img src=x onerror=alert(1)>",           // Event handler injection
		"\"><svg/onload=confirm(1)>",                // SVG-based injection
		"javascript:alert(1)",                       // JavaScript protocol injection
		"'><script>alert(document.domain)</script>", // DOM-based injection
	}

	// Configure HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Test each payload in different parameter contexts
	for _, payload := range payloads {
		testURLs := []string{
			url + "?q=" + payload,      // Query parameter
			url + "?search=" + payload, // Search parameter
			url + "?id=" + payload,     // ID parameter
		}

		for _, testURL := range testURLs {
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Read and analyze response body
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			bodyStr := string(body)

			// Check for payload reflection in response
			encodedPayload := neturl.QueryEscape(payload)
			if strings.Contains(bodyStr, payload) ||
				strings.Contains(bodyStr, encodedPayload) {

				// Additional context checks for successful injection
				lowerBody := strings.ToLower(bodyStr)
				if strings.Contains(lowerBody, "<script") ||
					strings.Contains(lowerBody, "onerror=") ||
					strings.Contains(lowerBody, "onload=") ||
					strings.Contains(lowerBody, "javascript:") {
					return true
				}
			}
		}
	}

	return false
}
