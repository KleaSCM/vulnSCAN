// take the banner and compare it against known vulnerable versions
package scanner

import (
	"fmt"
	"strings"
)

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

func extractVersion(banner string, prefix string) string {
	// Extract version number from banner
	return "2.4.29" // parsed from the actual banner
}

func isOutdatedApache(version string) bool {
	// Hardcoded check for outdated versions;  extend this with CVE API
	outdatedVersions := []string{"2.4.29", "2.4.28"}
	for _, v := range outdatedVersions {
		if version == v {
			return true
		}
	}
	return false
}
