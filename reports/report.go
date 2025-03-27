// Package reports provides functionality for generating and displaying security scan reports
// in multiple formats including HTML, JSON, and plain text. It handles both the web interface
// for displaying real-time scan results and the generation of downloadable report files.
package reports

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strings"
	"vulnSCAN/scanner"
)

// Severity represents the security impact level of a vulnerability
type Severity string

const (
	SeverityLow    = "Low"    // Minor security concerns
	SeverityMedium = "Medium" // Significant but not critical issues
	SeverityHigh   = "High"   // Critical security vulnerabilities
)

// Vulnerability represents a detected security issue with metadata
type Vulnerability struct {
	Name        string `json:"name"`        // Name of the vulnerability
	Description string `json:"description"` // Detailed description of the issue
	Severity    string `json:"severity"`    // Impact level of the vulnerability (Low/Medium/High)
	Found       bool   `json:"found"`       // Whether the vulnerability was detected
}

// ScanReport defines the structure of the scan report.
type ScanReport struct {
	Host            string                   `json:"host"`
	OpenPorts       map[int]bool             `json:"open_ports"`
	HTTPHeaders     map[string]string        `json:"http_headers"`
	Banners         map[int]string           `json:"banners"`
	CrawlResults    []string                 `json:"crawl_results"`
	Vulnerabilities map[string]Vulnerability `json:"vulnerabilities"`
	SSLInfo         map[string]string        `json:"ssl_info"`
	MissingHeaders  []Vulnerability          `json:"missing_headers"`
	ExposedFiles    []scanner.FileExposure   `json:"exposed_files"` // Updated type
	RobotsInfo      *scanner.RobotsInfo      `json:"robots_info"`   // Added robots.txt info
	DiscoveredPages []scanner.PageInfo       `json:"discovered_pages"`
}

// HTML template for displaying reports
const reportTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>VulnSCAN Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }
        .section {
            margin: 20px 0;
        }
        .section h2 {
            color: #444;
            margin-bottom: 10px;
        }
        ul {
            list-style-type: none;
            padding: 0;
        }
        li {
            padding: 8px;
            border-bottom: 1px solid #eee;
        }
        li:last-child {
            border-bottom: none;
        }
        .scan-form {
            margin: 20px 0;
            padding: 20px;
            background-color: #f8f9fa;
            border-radius: 8px;
        }
        .scan-form input[type="text"] {
            width: 100%;
            padding: 8px;
            margin: 8px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .scan-form button {
            background-color: #007bff;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        .scan-form button:hover {
            background-color: #0056b3;
        }
        .loading {
            display: none;
            text-align: center;
            margin: 20px 0;
        }
        .vulnerability {
            padding: 10px;
            margin: 5px 0;
            border-radius: 4px;
        }
        .vulnerable {
            background-color: #ffebee;
            color: #c62828;
        }
        .safe {
            background-color: #e8f5e9;
            color: #2e7d32;
        }
        .severity-high {
            background-color: #ffebee;
            color: #c62828;
            border-left: 4px solid #c62828;
        }
        .severity-medium {
            background-color: #fff3e0;
            color: #ef6c00;
            border-left: 4px solid #ef6c00;
        }
        .severity-low {
            background-color: #e8f5e9;
            color: #2e7d32;
            border-left: 4px solid #2e7d32;
        }
        .vulnerability-item {
            padding: 10px;
            margin: 5px 0;
            border-radius: 4px;
        }
        .discovered-pages {
            margin-top: 15px;
        }
        .page-item {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            border: 1px solid #e9ecef;
        }
        .page-item h3 {
            margin: 0 0 10px 0;
            color: #2c3e50;
        }
        .page-item a {
            color: #007bff;
            text-decoration: none;
        }
        .page-item a:hover {
            text-decoration: underline;
        }
        .page-details {
            font-size: 0.9em;
        }
        .has-form {
            color: #28a745;
            margin: 5px 0;
        }
        .keywords {
            margin-top: 10px;
        }
        .keywords ul {
            list-style: none;
            padding: 0;
            margin: 5px 0;
        }
        .keywords li {
            display: inline-block;
            margin: 2px 5px;
            padding: 3px 8px;
            background: #e9ecef;
            border-radius: 4px;
        }
        code {
            background: #f1f3f5;
            padding: 2px 5px;
            border-radius: 3px;
            color: #e83e8c;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>VulnSCAN Web Interface</h1>
        
        <div class="scan-form">
            <form id="scanForm" method="POST" action="/">
                <label for="host">Enter web address to scan:</label>
                <input type="text" id="host" name="host" placeholder="example.com" required>
                <button type="submit">Start Scan</button>
            </form>
            <div id="loading" class="loading">Scanning in progress...</div>
        </div>

        {{if .Host}}
        <h1>Scan Report for {{.Host}}</h1>
        
        <div class="section">
            <h2>Open Ports</h2>
            <ul>
                {{range $port, $_ := .OpenPorts}}
                <li>Port {{$port}}: Open</li>
                {{end}}
            </ul>
        </div>

        <div class="section">
            <h2>Banner Information</h2>
            <ul>
                {{range $port, $banner := .Banners}}
                <li><strong>Port {{$port}}:</strong> {{$banner}}</li>
                {{end}}
            </ul>
        </div>

        <div class="section">
            <h2>HTTP Headers</h2>
            <ul>
                {{range $header, $value := .HTTPHeaders}}
                <li><strong>{{$header}}:</strong> {{$value}}</li>
                {{end}}
            </ul>
        </div>

        <div class="section">
            <h2>Crawl Results</h2>
            <ul>
                {{range .CrawlResults}}
                <li>{{.}}</li>
                {{end}}
            </ul>
        </div>

        <div class="section">
            <h2>Security Vulnerabilities</h2>
            {{range $name, $vuln := .Vulnerabilities}}
                <div class="vulnerability-item severity-{{lower $vuln.Severity}}">
                    <strong>{{$vuln.Name}}</strong>: {{$vuln.Description}}
                    <br>
                    <small>Severity: {{$vuln.Severity}}</small>
                </div>
            {{end}}
        </div>

        <div class="section">
            <h2>Missing Security Headers</h2>
            {{range .MissingHeaders}}
                <div class="vulnerability-item severity-{{lower .Severity}}">
                    <strong>{{.Name}}</strong>: {{.Description}}
                    <br>
                    <small>Severity: {{.Severity}}</small>
                </div>
            {{end}}
        </div>

        <div class="section">
            <h2>SSL/TLS Information</h2>
            <ul>
                {{range $key, $value := .SSLInfo}}
                <li><strong>{{$key}}:</strong> {{$value}}</li>
                {{end}}
            </ul>
        </div>

        <div class="section">
            <h2>Discovered Pages</h2>
            <div class="discovered-pages">
                {{range .DiscoveredPages}}
                <div class="page-item">
                    <h3><a href="{{.URL}}" target="_blank">{{.PageTitle}}</a></h3>
                    <div class="page-details">
                        <p class="url"><strong>URL:</strong> {{.URL}}</p>
                        {{if .HasForm}}
                        <p class="has-form">📝 Contains form submission</p>
                        {{end}}
                        {{if .Keywords}}
                        <div class="keywords">
                            <strong>🔍 Found Keywords:</strong>
                            <ul>
                            {{range .Keywords}}
                                <li><code>{{.}}</code></li>
                            {{end}}
                            </ul>
                        </div>
                        {{end}}
                    </div>
                </div>
                {{end}}
            </div>
        </div>

        <div class="section">
            <h2>Exposed Files</h2>
            <ul>
                {{range .ExposedFiles}}
                <li><strong>{{.Path}}</strong> (Status: {{.StatusCode}})</li>
                {{end}}
            </ul>
        </div>
        {{end}}
    </div>

    <script>
        document.getElementById('scanForm').onsubmit = function() {
            document.getElementById('loading').style.display = 'block';
        };
    </script>
</body>
</html>
`

// handleReport processes scan requests and generates the security report
// This function:
// 1. Handles both GET (form display) and POST (scan execution) requests
// 2. Coordinates all security scanning operations
// 3. Generates reports in multiple formats
// 4. Renders results in the web interface
func handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		host := r.FormValue("host")
		if host == "" {
			http.Error(w, "Host is required", http.StatusBadRequest)
			return
		}

		// Normalize the URL
		baseURL := host
		if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
			baseURL = "http://" + host
		}

		// Extract hostname for SSL check
		hostname := host
		if strings.Contains(host, "://") {
			hostname = strings.Split(host, "://")[1]
		}
		if strings.Contains(hostname, "/") {
			hostname = strings.Split(hostname, "/")[0]
		}

		// Perform the scan
		ports := []int{80, 443, 22, 8080}
		openPorts := scanner.ScanPorts(hostname, ports)

		// Get banner information
		banners := make(map[int]string)
		for port, isOpen := range openPorts {
			if isOpen {
				banners[port] = scanner.GrabBanner(hostname, port)
			}
		}

		// Check HTTP headers
		headers := scanner.GetHTTPHeaders(baseURL)

		// Perform crawl
		crawlResults, robotsInfo := scanner.CrawlURLs(baseURL)

		// Test for vulnerabilities
		sqliVulnerable := scanner.TestSQLiVulnerability(baseURL)
		xssVulnerable := scanner.TestXSSVulnerability(baseURL)

		// Check SSL/TLS
		sslInfo := scanner.GetSSLInfo(hostname, 443)

		// Create vulnerabilities map
		vulnerabilities := make(map[string]Vulnerability)

		// SQL Injection check
		if sqliVulnerable {
			vulnerabilities["sql_injection"] = Vulnerability{
				Name:        "SQL Injection",
				Description: "Application appears vulnerable to SQL injection attacks",
				Severity:    SeverityHigh,
				Found:       true,
			}
		}

		// XSS check
		if xssVulnerable {
			vulnerabilities["xss"] = Vulnerability{
				Name:        "Cross-Site Scripting (XSS)",
				Description: "Application appears vulnerable to cross-site scripting attacks",
				Severity:    SeverityMedium,
				Found:       true,
			}
		}

		// Check for missing security headers
		missingHeaders := []Vulnerability{}
		criticalHeaders := map[string]Vulnerability{
			"Strict-Transport-Security": {
				Name:        "Missing HSTS Header",
				Description: "The HTTP Strict Transport Security header is not set",
				Severity:    SeverityLow,
				Found:       true,
			},
			"Content-Security-Policy": {
				Name:        "Missing CSP Header",
				Description: "The Content Security Policy header is not set",
				Severity:    SeverityLow,
				Found:       true,
			},
			"X-Frame-Options": {
				Name:        "Missing X-Frame-Options Header",
				Description: "The X-Frame-Options header is not set",
				Severity:    SeverityLow,
				Found:       true,
			},
		}

		for header, vuln := range criticalHeaders {
			if headers[header] == "MISSING" {
				missingHeaders = append(missingHeaders, vuln)
			}
		}

		// Check for exposed files
		exposedFiles := scanner.CheckCommonFiles(baseURL)

		// Create the report
		report := ScanReport{
			Host:            host,
			OpenPorts:       openPorts,
			HTTPHeaders:     headers,
			Banners:         banners,
			CrawlResults:    crawlResults,
			Vulnerabilities: vulnerabilities,
			SSLInfo:         sslInfo,
			MissingHeaders:  missingHeaders,
			ExposedFiles:    exposedFiles,
			RobotsInfo:      robotsInfo,
		}

		// Generate JSON and text report files with sanitized hostname in filename
		// Sanitization replaces dots, slashes and colons with underscores to create
		// a safe filename that works across operating systems
		safeHost := strings.ReplaceAll(hostname, ".", "_")
		safeHost = strings.ReplaceAll(safeHost, "/", "_")
		safeHost = strings.ReplaceAll(safeHost, ":", "_")
		jsonFilename := fmt.Sprintf("%s_scan_report.json", safeHost)
		textFilename := fmt.Sprintf("%s_scan_report.txt", safeHost)

		GenerateJSONReport(report, jsonFilename)
		GenerateTextReport(report, textFilename)

		// Display the report
		tmpl, err := template.New("report").Funcs(template.FuncMap{
			"lower": strings.ToLower,
		}).Parse(reportTemplate)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := tmpl.Execute(w, report); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Handle GET request - show the form
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"lower": strings.ToLower,
	}).Parse(reportTemplate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, ScanReport{}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// GenerateJSONReport creates a detailed JSON report file from the scan results
// Parameters:
//   - report: The completed ScanReport structure
//   - filename: The target filename for the JSON report
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

// GenerateTextReport creates a human-readable text report file
// Parameters:
//   - report: The completed ScanReport structure
//   - filename: The target filename for the text report
//
// The text report includes sections for:
//   - Basic target information
//   - Open ports and services
//   - Security headers
//   - Vulnerabilities
//   - SSL/TLS configuration
//   - Exposed files
func GenerateTextReport(report ScanReport, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Failed to create report file: %v\n", err)
		return
	}
	defer file.Close()

	// Write the report content in a human-readable format
	if _, err = fmt.Fprintf(file, "Scan Report for Host: %s\n", report.Host); err != nil {
		fmt.Printf("Failed to write host: %v\n", err)
		return
	}

	if _, err = fmt.Fprintf(file, "\nOpen Ports:\n"); err != nil {
		fmt.Printf("Failed to write ports header: %v\n", err)
		return
	}
	for port := range report.OpenPorts {
		if _, err = fmt.Fprintf(file, "- Port %d: Open\n", port); err != nil {
			fmt.Printf("Failed to write port entry: %v\n", err)
			return
		}
	}

	if _, err = fmt.Fprintf(file, "\nBanner Information:\n"); err != nil {
		fmt.Printf("Failed to write banner header: %v\n", err)
		return
	}
	for port, banner := range report.Banners {
		if _, err = fmt.Fprintf(file, "- Port %d: %s\n", port, banner); err != nil {
			fmt.Printf("Failed to write banner entry: %v\n", err)
			return
		}
	}

	if _, err = fmt.Fprintf(file, "\nHTTP Headers:\n"); err != nil {
		fmt.Printf("Failed to write headers header: %v\n", err)
		return
	}
	for header, value := range report.HTTPHeaders {
		if _, err = fmt.Fprintf(file, "- %s: %s\n", header, value); err != nil {
			fmt.Printf("Failed to write header entry: %v\n", err)
			return
		}
	}

	if _, err = fmt.Fprintf(file, "\nCrawl Results:\n"); err != nil {
		fmt.Printf("Failed to write crawl header: %v\n", err)
		return
	}
	for _, result := range report.CrawlResults {
		if _, err = fmt.Fprintf(file, "- %s\n", result); err != nil {
			fmt.Printf("Failed to write crawl entry: %v\n", err)
			return
		}
	}

	if _, err = fmt.Fprintf(file, "\nSecurity Vulnerabilities:\n"); err != nil {
		fmt.Printf("Failed to write vulnerabilities header: %v\n", err)
		return
	}
	for _, vuln := range report.Vulnerabilities {
		if _, err = fmt.Fprintf(file, "- %s: %s\n", vuln.Name, vuln.Description); err != nil {
			fmt.Printf("Failed to write vulnerability entry: %v\n", err)
			return
		}
	}

	if _, err = fmt.Fprintf(file, "\nSSL/TLS Information:\n"); err != nil {
		fmt.Printf("Failed to write SSL header: %v\n", err)
		return
	}
	for key, value := range report.SSLInfo {
		if _, err = fmt.Fprintf(file, "- %s: %s\n", key, value); err != nil {
			fmt.Printf("Failed to write SSL entry: %v\n", err)
			return
		}
	}

	if _, err = fmt.Fprintf(file, "\nExposed Files:\n"); err != nil {
		fmt.Printf("Failed to write exposed files header: %v\n", err)
		return
	}
	for _, exposedFile := range report.ExposedFiles {
		if _, err = fmt.Fprintf(file, "- %s (Status: %d)\n", exposedFile.Path, exposedFile.StatusCode); err != nil {
			fmt.Printf("Failed to write exposed file entry: %v\n", err)
			return
		}
	}
}
