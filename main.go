package main

import (
	"bufio"
	"fmt"
	"os"
	"vulnSCAN/reports"
	"vulnSCAN/scanner"
)

func main() {
	// Step 1: Prompt the user for a web address
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the web address to scan (e.g., example.com): ")
	host, _ := reader.ReadString('\n')
	host = host[:len(host)-1] // Remove the newline character

	// Step 2: Scan for open ports
	ports := []int{80, 443, 22, 8080}
	openPorts := scanner.ScanPorts(host, ports)
	fmt.Println("Open ports:", openPorts)

	// Step 3: Banner grabbing for open ports
	for port, isOpen := range openPorts {
		if isOpen {
			banner := scanner.GrabBanner(host, port)
			fmt.Printf("Banner for port %d: %s\n", port, banner)

			// Step 4: Detect outdated software based on banners
			scanner.DetectOutdatedSoftware(banner)

			// Step 5: SSL/TLS check for HTTPS ports (like 443)
			if port == 443 {
				scanner.CheckTLS(host, port)
			}
		}
	}

	// Step 6: Check HTTP/HTTPS security headers
	fmt.Println("\nChecking HTTP headers...")
	scanner.CheckHTTPHeaders("http://" + host)

	// Step 7: Check for common sensitive files
	fmt.Println("\nChecking for common sensitive files...")
	scanner.CheckCommonFiles("http://" + host)

	// Step 8: Basic testing for SQL Injection and XSS vulnerabilities
	fmt.Println("\nTesting for SQL Injection and XSS vulnerabilities...")
	scanner.TestSQLi("http://" + host)
	scanner.TestXSS("http://" + host)

	// Step 9: Generate a report with the scan results
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
