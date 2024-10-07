package scanner

import (
	"fmt"
	"net/http"
)

func CheckCommonFiles(url string) {
	files := []string{
		"/.env",
		"/backup.zip",
		"/.git/",
	}

	for _, file := range files {
		checkFile(url + file)
	}
}

func checkFile(url string) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Failed to check %s: %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Printf("Potentially exposed file: %s\n", url)
	}
}
