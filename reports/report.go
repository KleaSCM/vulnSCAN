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

// ScanReport defines the structure of the scan report.
type ScanReport struct {
	Host           string            `json:"host"`
	OpenPorts      map[int]bool      `json:"open_ports"`
	HTTPHeaders    map[string]string `json:"http_headers"`
	Banners        map[int]string    `json:"banners"`
	CrawlResults   []string          `json:"crawl_results"`
	SQLiVulnerable bool              `json:"sql_injection_vulnerable"`
	XSSVulnerable  bool              `json:"xss_vulnerable"`
	SSLInfo        map[string]string `json:"ssl_info"`
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
            <div class="vulnerability {{if .SQLiVulnerable}}vulnerable{{else}}safe{{end}}">
                SQL Injection: {{if .SQLiVulnerable}}Vulnerable{{else}}Safe{{end}}
            </div>
            <div class="vulnerability {{if .XSSVulnerable}}vulnerable{{else}}safe{{end}}">
                XSS: {{if .XSSVulnerable}}Vulnerable{{else}}Safe{{end}}
            </div>
        </div>

        <div class="section">
            <h2>SSL/TLS Information</h2>
            <ul>
                {{range $key, $value := .SSLInfo}}
                <li><strong>{{$key}}:</strong> {{$value}}</li>
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

// handleReport serves the HTML report page by processing the scan form submission,
// performing security scans on the provided host (including port scanning, banner grabbing,
// HTTP header checks, crawling, vulnerability testing, and SSL/TLS analysis), and
// rendering the results using the HTML template
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
		crawlResults := scanner.CrawlURLs(baseURL)

		// Test for vulnerabilities
		sqliVulnerable := scanner.TestSQLiVulnerability(baseURL)
		xssVulnerable := scanner.TestXSSVulnerability(baseURL)

		// Check SSL/TLS
		sslInfo := scanner.GetSSLInfo(hostname, 443)

		// Create the report
		report := ScanReport{
			Host:           host,
			OpenPorts:      openPorts,
			HTTPHeaders:    headers,
			Banners:        banners,
			CrawlResults:   crawlResults,
			SQLiVulnerable: sqliVulnerable,
			XSSVulnerable:  xssVulnerable,
			SSLInfo:        sslInfo,
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
		tmpl, err := template.New("report").Parse(reportTemplate)
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
	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, ScanReport{}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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
	if _, err = fmt.Fprintf(file, "- SQL Injection: %v\n", report.SQLiVulnerable); err != nil {
		fmt.Printf("Failed to write SQLi status: %v\n", err)
		return
	}
	if _, err = fmt.Fprintf(file, "- XSS: %v\n", report.XSSVulnerable); err != nil {
		fmt.Printf("Failed to write XSS status: %v\n", err)
		return
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
}
