package scanner

import (
	"fmt"
	"net/http"
)

func CheckHTTPHeaders(url string) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Failed to fetch %s: %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	securityHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
	}

	fmt.Println("Security headers detected:")
	for _, header := range securityHeaders {
		if val := resp.Header.Get(header); val != "" {
			fmt.Printf("%s: %s\n", header, val)
		} else {
			fmt.Printf("%s: MISSING\n", header)
		}
	}
}
