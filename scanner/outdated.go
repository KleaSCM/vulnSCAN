// Package scanner provides security scanning capabilities for web applications
package scanner

import (
	"fmt"
	"strings"
)

// DetectOutdatedSoftware analyzes server banners to identify outdated software versions
// that may be vulnerable to known security issues. Currently supports:
// 1. Apache HTTP Server version detection
// 2. Version comparison against known vulnerable versions
// 3. Future extensibility for other software types
func DetectOutdatedSoftware(banner string) {
	// Detect outdated Apache HTTP server versions
	if strings.Contains(banner, "Apache") {
		version := extractVersion(banner, "Apache/")
		if isOutdatedApache(version) {
			fmt.Printf("Detected outdated Apache version: %s\n", version)
		} else {
			fmt.Printf("Apache version %s is up to date\n", version)
		}
	}
}

// extractVersion parses version numbers from software banners
// Parameters:
//   - banner: The full server banner string
//   - prefix: The software identifier (e.g., "Apache/")
//
// Returns:
//   - The extracted version number or empty string if not found
func extractVersion(banner string, prefix string) string {
	if strings.Contains(banner, prefix) {
		parts := strings.Split(banner, prefix)
		if len(parts) > 1 {
			version := strings.Split(parts[1], " ")[0]
			return version
		}
	}
	return ""
}

// isOutdatedApache checks if an Apache version is known to be vulnerable
// Parameters:
//   - version: The Apache version string to check
//
// Returns:
//   - true if the version is known to be vulnerable
//   - false if the version is current or unknown
//
// Note: This is a simplified check. In a production environment, this should:
// 1. Use a CVE database API
// 2. Consider version ranges rather than exact matches
// 3. Include more version information
func isOutdatedApache(version string) bool {
	// Hardcoded check for outdated versions; extend this with CVE API
	outdatedVersions := []string{"2.4.29", "2.4.28"}
	for _, v := range outdatedVersions {
		if version == v {
			return true
		}
	}
	return false
}
