package reports

import (
	"encoding/json"
	"fmt"
	"os"
)

type ScanReport struct {
	Host        string            `json:"host"`
	OpenPorts   map[int]bool      `json:"open_ports"`
	HTTPHeaders map[string]string `json:"http_headers"`
}

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
