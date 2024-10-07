package main

import (
	"fmt"
	"vulnscanner/reports"
	"vulnscanner/scanner"
)

func main() {
	host := "example.com"

	// Step 1: Scan open ports
	ports := []int{80, 443, 22, 8080}
	openPorts := scanner.ScanPorts(host, ports)
	fmt.Println("Open ports:", openPorts)

	// Step 2: Grab banners for open ports
	for port, isOpen := range openPorts {
		if isOpen {
			banner := scanner.GrabBanner(host, port)
			fmt.Printf("Banner for port %d: %s\n", port, banner)

			// Step 3: Detect outdated software based on banners
			scanner.DetectOutdatedSoftware(banner)

			// Step 4: SSL/TLS check for HTTPS ports
			if port == 443 {
				scanner.CheckTLS(host, port)
			}
		}
	}

	// Step 5: Check HTTP/HTTPS security headers
	fmt.Println("\nChecking HTTP headers...")
	scanner.CheckHTTPHeaders("http://" + host)

	// Step 6: Check for common sensitive files
	fmt.Println("\nChecking for common sensitive files...")
	scanner.CheckCommonFiles("http://" + host)

	// Step 7: Perform SQLi and XSS tests
	fmt.Println("\nTesting for SQL Injection and XSS vulnerabilities...")
	scanner.TestSQLi("http://" + host)
	scanner.TestXSS("http://" + host)

	// Generate report
	report := reports.ScanReport{
		Host:      host,
		OpenPorts: openPorts,
		// Collecting a dummy header response for now. Populate real headers in real scenarios.
		HTTPHeaders: map[string]string{
			"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		},
	}

	// Step 8: Output the results to a JSON file
	fmt.Println("\nGenerating JSON report...")
	reports.GenerateJSONReport(report, "scan_report.json")
	fmt.Println("Report saved to scan_report.json")
}
