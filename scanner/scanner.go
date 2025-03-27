package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Crawl performs a basic web crawl and returns discovered URLs
func Crawl(url string) []string {
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

// TestSQLi tests for SQL injection vulnerabilities and returns the result
func TestSQLi(url string) bool {
	testURL := url + "?id=1' OR '1'='1"
	resp, err := http.Get(testURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

// TestXSS tests for XSS vulnerabilities and returns the result
func TestXSS(url string) bool {
	testURL := url + "?q=<script>alert(1)</script>"
	resp, err := http.Get(testURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

// CheckTLS checks SSL/TLS configuration and returns the information
func CheckTLS(host string, port int) map[string]string {
	info := make(map[string]string)
	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		info["error"] = fmt.Sprintf("Error connecting to %s: %v", address, err)
		return info
	}
	defer conn.Close()

	state := conn.ConnectionState()
	info["version"] = tlsVersionString(state.Version)
	info["cipher"] = tls.CipherSuiteName(state.CipherSuite)

	return info
}

// CheckHTTPHeaders checks security headers and returns them
func CheckHTTPHeaders(url string) map[string]string {
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

// tlsVersionString converts TLS version number to string
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return "Unknown"
	}
}

// GetSSLInfo checks SSL/TLS configuration and returns the information
func GetSSLInfo(host string, port int) map[string]string {
	info := make(map[string]string)
	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		info["error"] = fmt.Sprintf("Error connecting to %s: %v", address, err)
		return info
	}
	defer conn.Close()

	state := conn.ConnectionState()
	info["version"] = tlsVersionString(state.Version)
	info["cipher"] = tls.CipherSuiteName(state.CipherSuite)

	return info
}
