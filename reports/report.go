// reports/report.go
package reports

import (
	"encoding/json"
	"fmt"
	"os"
)

// ScanReport defines the structure of the scan report.
type ScanReport struct {
	Host        string            `json:"host"`
	OpenPorts   map[int]bool      `json:"open_ports"`
	HTTPHeaders map[string]string `json:"http_headers"`
}

// GenerateJSONReport creates a JSON report file from the given ScanReport.
func GenerateJSONReport(report ScanReport, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Failed to create report file: %v\n", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(report)
	if err != nil {
		fmt.Printf("Failed to write report: %v\n", err)
	}
}

// GenerateTextReport creates a text report file from the given ScanReport.
func GenerateTextReport(report ScanReport, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Failed to create report file: %v\n", err)
		return
	}
	defer file.Close()

	// Write the report content in a human-readable format
	_, err = fmt.Fprintf(file, "Scan Report for Host: %s\n", report.Host)
	_, err = fmt.Fprintf(file, "Open Ports:\n")
	for port := range report.OpenPorts {
		_, err = fmt.Fprintf(file, "- Port %d: Open\n", port)
	}

	_, err = fmt.Fprintf(file, "\nHTTP Headers:\n")
	for header, value := range report.HTTPHeaders {
		_, err = fmt.Fprintf(file, "- %s: %s\n", header, value)
	}

	if err != nil {
		fmt.Printf("Failed to write report: %v\n", err)
	}
}
