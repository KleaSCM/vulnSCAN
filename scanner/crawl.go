// Package scanner provides security scanning capabilities for web applications
package scanner

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// SitemapURL represents a URL entry in a sitemap.xml file
type SitemapURL struct {
	Loc string `xml:"loc"` // The URL location in the sitemap
}

// Sitemap represents the structure of a sitemap.xml file
type Sitemap struct {
	URLs []SitemapURL `xml:"url"` // List of URLs in the sitemap
}

// ExposedFile represents a potentially exposed sensitive file
type ExposedFile struct {
	Path       string // The URL path of the exposed file
	StatusCode int    // HTTP status code of the response
}

// RobotsInfo stores parsed robots.txt information with severity levels
type RobotsInfo struct {
	RawContent   string
	Allow        []string
	Disallow     []string
	Sitemaps     []string
	OpenIndexing bool
	// Track interesting paths for reporting
	InterestingPaths []InterestingPath
}

// InterestingPath represents a notable path from robots.txt
type InterestingPath struct {
	Path     string
	Reason   string
	LogLevel string // "INFO", "WARNING", "ALERT"
}

// FileExposure represents the exposure level of a discovered file
type FileExposure struct {
	Path       string
	StatusCode int
	Severity   string // "EXPOSED", "SUSPICIOUS", "PROTECTED", "SAFE"
}

// parseRobotsTxt fetches and parses robots.txt to discover paths and generate reports
// Returns both the discovered paths and detailed robots.txt information
func parseRobotsTxt(baseURL string) ([]string, *RobotsInfo) {
	var paths []string
	info := &RobotsInfo{
		OpenIndexing: true,
	}
	robotsURL := baseURL + "/robots.txt"
	resp, err := http.Get(robotsURL)
	if err != nil {
		return paths, info
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return paths, info
	}

	// Parse each line with enhanced logging
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(line, "Allow:"):
			path := strings.TrimSpace(strings.TrimPrefix(line, "Allow:"))
			info.Allow = append(info.Allow, path)
			paths = append(paths, path)

		case strings.HasPrefix(line, "Disallow:"):
			path := strings.TrimSpace(strings.TrimPrefix(line, "Disallow:"))
			info.Disallow = append(info.Disallow, path)
			if path != "" {
				info.OpenIndexing = false
			}
			paths = append(paths, path)

			// Check for interesting paths
			if reason := checkInterestingPath(path); reason != "" {
				interesting := InterestingPath{
					Path:     path,
					Reason:   reason,
					LogLevel: "WARNING",
				}
				info.InterestingPaths = append(info.InterestingPaths, interesting)

				// Log to console
				fmt.Printf("[ROBOTS.TXT WARNING] Interesting path found: %s - %s\n", path, reason)

				// Could also log to file:
				// logToFile(fmt.Sprintf("[ROBOTS.TXT] Found interesting path: %s - %s\n", path, reason))
			}

		case strings.HasPrefix(line, "Sitemap:"):
			sitemap := strings.TrimSpace(strings.TrimPrefix(line, "Sitemap:"))
			info.Sitemaps = append(info.Sitemaps, sitemap)
		}
	}

	// Save the files
	saveRobotsFiles(baseURL, info)

	return paths, info
}

// saveRobotsFiles saves both raw robots.txt and a markdown analysis
func saveRobotsFiles(baseURL string, info *RobotsInfo) {
	// Create safe filename from hostname
	hostname := strings.TrimPrefix(baseURL, "http://")
	hostname = strings.TrimPrefix(hostname, "https://")
	hostname = strings.ReplaceAll(hostname, "/", "_")
	hostname = strings.ReplaceAll(hostname, ":", "_")

	// Save raw content
	rawFilename := hostname + "_robots.txt"
	err := os.WriteFile(rawFilename, []byte(info.RawContent), 0644)
	if err != nil {
		fmt.Printf("Failed to save robots.txt: %v\n", err)
	}

	// Generate markdown analysis
	var md strings.Builder
	md.WriteString("# Robots.txt Analysis\n\n")

	if info.OpenIndexing {
		md.WriteString("⚠️ **Note:** No indexing restrictions found - site is fully indexable\n\n")
	}

	// Write Allow directives
	md.WriteString("## Allow Directives\n")
	if len(info.Allow) == 0 {
		md.WriteString("- None specified\n")
	} else {
		for _, path := range info.Allow {
			md.WriteString(fmt.Sprintf("- `%s`\n", path))
		}
	}
	md.WriteString("\n")

	// Write Disallow directives
	md.WriteString("## Disallow Directives\n")
	if len(info.Disallow) == 0 {
		md.WriteString("- None specified\n")
	} else {
		for _, path := range info.Disallow {
			md.WriteString(fmt.Sprintf("- `%s`", path))
			// Highlight interesting paths
			if isInterestingPath(path) {
				md.WriteString(" ⚠️")
			}
			md.WriteString("\n")
		}
	}
	md.WriteString("\n")

	// Write Sitemaps
	md.WriteString("## Sitemaps\n")
	if len(info.Sitemaps) == 0 {
		md.WriteString("- None specified\n")
	} else {
		for _, sitemap := range info.Sitemaps {
			md.WriteString(fmt.Sprintf("- %s\n", sitemap))
		}
	}

	// Save markdown analysis
	mdFilename := hostname + "_robots.md"
	err = os.WriteFile(mdFilename, []byte(md.String()), 0644)
	if err != nil {
		fmt.Printf("Failed to save robots analysis: %v\n", err)
	}
}

// isInterestingPath checks if a path might contain sensitive information
func isInterestingPath(path string) bool {
	interesting := []string{
		"admin", "backup", "wp-", "phpmy", "sql",
		".git", ".env", "config", "test", "dev",
		"api", "internal", "private", "secret",
	}

	path = strings.ToLower(path)
	for _, pattern := range interesting {
		if strings.Contains(path, pattern) {
			return true
		}
	}
	return false
}

// parseSitemapXML fetches and parses sitemap.xml to discover:
// 1. All public URLs of the website
// 2. Site structure and hierarchy
// 3. Hidden or less obvious pages
//
// Returns a slice of URLs found in the sitemap.
func parseSitemapXML(baseURL string) []string {
	var urls []string
	sitemapURL := baseURL + "/sitemap.xml"
	resp, err := http.Get(sitemapURL)
	if err != nil {
		return urls
	}
	defer resp.Body.Close()

	// Parse XML structure
	var sitemap Sitemap
	if err := xml.NewDecoder(resp.Body).Decode(&sitemap); err != nil {
		return urls
	}

	// Extract all URLs from the sitemap
	for _, sitemapURL := range sitemap.URLs {
		urls = append(urls, sitemapURL.Loc)
	}
	return urls
}

// CheckCommonFiles scans for commonly exposed sensitive files that could:
// 1. Reveal configuration details
// 2. Expose source code
// 3. Leak sensitive information
// 4. Provide access to backup files
//
// Returns a slice of ExposedFile structs containing discovered files.
func CheckCommonFiles(baseURL string) []FileExposure {
	var exposures []FileExposure
	files := []string{
		"/.env",
		"/backup.zip",
		"/.git/",
		"/config.php",
		"/wp-config.php",
		"/.htaccess",
	}

	for _, file := range files {
		if exposure := checkFileExposure(baseURL + file); exposure != nil {
			exposures = append(exposures, *exposure)
		}
	}

	return exposures
}

func determineExposureSeverity(statusCode int) string {
	switch statusCode {
	case 200:
		return "EXPOSED"
	case 401, 403:
		return "PROTECTED"
	case 404:
		return "SAFE"
	default:
		return "SUSPICIOUS"
	}
}

// checkFile verifies if a specific file is accessible via HTTP
// Returns an ExposedFile struct if the file is accessible, nil otherwise
func checkFileExposure(url string) *FileExposure {
	resp, err := http.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	return &FileExposure{
		Path:       url,
		StatusCode: resp.StatusCode,
		Severity:   determineExposureSeverity(resp.StatusCode),
	}
}

// checkInterestingPath returns a reason if the path is interesting
func checkInterestingPath(path string) string {
	patterns := map[string]string{
		"admin":    "Potential admin interface",
		"backup":   "Possible backup files",
		".git":     "Git repository",
		"wp-":      "WordPress files",
		"config":   "Configuration files",
		"test":     "Test environment",
		"dev":      "Development files",
		"internal": "Internal resources",
		"api":      "API endpoint",
		"secret":   "Potentially sensitive data",
	}

	for pattern, reason := range patterns {
		if strings.Contains(strings.ToLower(path), pattern) {
			return reason
		}
	}
	return ""
}

// CrawlURLs performs a comprehensive web crawl that:
// 1. Checks robots.txt for allowed/disallowed paths
// 2. Parses sitemap.xml for site structure
// 3. Scans for exposed sensitive files
// 4. Tests common web application paths
//
// Returns a slice of discovered URLs and detailed robots.txt information.
func CrawlURLs(baseURL string) ([]string, *RobotsInfo) {
	var results []string
	results = append(results, baseURL)

	// Parse robots.txt and sitemap.xml
	robotsPaths, robotsInfo := parseRobotsTxt(baseURL)
	results = append(results, robotsPaths...)
	results = append(results, parseSitemapXML(baseURL)...)

	// Check for exposed files
	exposedFiles := CheckCommonFiles(baseURL)
	for _, file := range exposedFiles {
		results = append(results, file.Path)
	}

	// Test common web application paths
	commonPaths := []string{
		"/",         // Root path
		"/admin",    // Admin interface
		"/login",    // Login page
		"/register", // Registration page
		"/api",      // API endpoints
	}

	// Check each common path
	for _, path := range commonPaths {
		testURL := baseURL + path
		resp, err := http.Get(testURL)
		if err == nil {
			results = append(results, testURL)
			resp.Body.Close()
		}
	}

	return results, robotsInfo
}
