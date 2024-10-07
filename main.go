package main

import (
	"fmt"
	"vulnSCAN/reports"
	"vulnSCAN/scanner"
)

func main() {
	// Target host for the scan
	host := "https://us.shop.battle.net/en-us?from=root"

	// Step 1: Scan for open ports
	ports := []int{80, 443, 22, 8080}
	openPorts := scanner.ScanPorts(host, ports)
	fmt.Println("Open ports:", openPorts)

	// Step 2: Banner grabbing for open ports
	for port, isOpen := range openPorts {
		if isOpen {
			banner := scanner.GrabBanner(host, port)
			fmt.Printf("Banner for port %d: %s\n", port, banner)

			// Step 3: Detect outdated software based on banners
			scanner.DetectOutdatedSoftware(banner)

			// Step 4: SSL/TLS check for HTTPS ports (like 443)
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

	// Step 7: Basic testing for SQL Injection and XSS vulnerabilities
	fmt.Println("\nTesting for SQL Injection and XSS vulnerabilities...")
	scanner.TestSQLi("http://" + host)
	scanner.TestXSS("http://" + host)

	// Step 8: Generate a report with the scan results
	report := reports.ScanReport{
		Host:      host,
		OpenPorts: openPorts,
		// Example: Add collected HTTP headers (use real headers during the actual scan)
		HTTPHeaders: map[string]string{
			"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		},
	}

	// Output the results to a JSON file
	fmt.Println("\nGenerating JSON report...")
	reports.GenerateJSONReport(report, "scan_report.json")
	fmt.Println("Report saved to scan_report.json")
}
