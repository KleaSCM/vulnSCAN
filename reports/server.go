package reports

import (
	"fmt"
	"log"
	"net/http"
)

// RunServer starts the report server and blocks until an error occurs
func RunServer() {
	fmt.Println("Starting VulnSCAN Report Server...")
	fmt.Println("Access the report at: http://localhost:6969")

	// Start the server
	if err := StartReportServer(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// StartReportServer starts a web server to display scan reports
func StartReportServer() error {
	http.HandleFunc("/", handleReport)
	fmt.Println("Starting report server on http://localhost:6969")
	return http.ListenAndServe(":6969", nil)
}
