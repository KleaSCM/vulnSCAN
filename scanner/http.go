package scanner

import (
	"fmt"
	"net/http"
)

// GetHTTPHeaders checks security headers and returns them
func GetHTTPHeaders(url string) map[string]string {
	headers := make(map[string]string)
	resp, err := http.Get(url)
	if err != nil {
		headers["error"] = fmt.Sprintf("Failed to fetch %s: %v", url, err)
		return headers
	}
	defer resp.Body.Close()

	securityHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
	}

	for _, header := range securityHeaders {
		if val := resp.Header.Get(header); val != "" {
			headers[header] = val
		} else {
			headers[header] = "MISSING"
		}
	}

	return headers
}
