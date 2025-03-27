package scanner

import (
	"io"
	"net/http"
	"strings"

	"golang.org/x/net/html"
)

// PageInfo represents information about a discovered webpage
type PageInfo struct {
	URL       string   `json:"url"`
	PageTitle string   `json:"page_title"`
	HasForm   bool     `json:"has_form"`
	Keywords  []string `json:"keywords"`
}

// AnalyzeSitemapPages fetches and analyzes pages from the sitemap
// to gather intelligence about the website structure and content
func AnalyzeSitemapPages(baseURL string) []PageInfo {
	var pages []PageInfo
	urls := parseSitemapXML(baseURL)

	for _, url := range urls {
		if page := analyzePage(url); page != nil {
			pages = append(pages, *page)
		}
	}

	return pages
}

// analyzePage fetches and analyzes a single page for intelligence gathering
func analyzePage(url string) *PageInfo {
	resp, err := http.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil
	}

	page := &PageInfo{
		URL:      url,
		Keywords: extractKeywords(doc),
		HasForm:  hasForm(doc),
	}
	page.PageTitle = extractTitle(doc)

	return page
}

// extractTitle gets the page title from HTML
func extractTitle(n *html.Node) string {
	if n.Type == html.ElementNode && n.Data == "title" {
		if n.FirstChild != nil {
			return n.FirstChild.Data
		}
		return ""
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if title := extractTitle(c); title != "" {
			return title
		}
	}
	return ""
}

// hasForm checks if the page contains any forms
func hasForm(n *html.Node) bool {
	if n.Type == html.ElementNode && n.Data == "form" {
		return true
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if hasForm(c) {
			return true
		}
	}
	return false
}

// extractKeywords gets important keywords from meta tags, scripts, body content,
// and HTML comments that might indicate sensitive information
func extractKeywords(n *html.Node) []string {
	var keywords []string

	// Common sensitive keywords to look for
	sensitivePatterns := []string{
		"FLAG{", "THM{", "CTF{", // CTF flags
		"debug", "test", "dev", // Development artifacts
		"token", "key", "secret", // Security tokens
		"password", "pwd", "auth", // Authentication
		"admin", "root", "sudo", // Administrative access
		"TODO", "FIXME", "HACK", // Developer comments
		"api", "endpoint", "internal", // API related
		"backup", "old", "deprecated", // Backup files
	}

	switch n.Type {
	case html.ElementNode:
		// Check meta keywords
		if n.Data == "meta" {
			for _, attr := range n.Attr {
				if attr.Key == "name" && attr.Val == "keywords" {
					for _, attr := range n.Attr {
						if attr.Key == "content" {
							keywords = append(keywords, strings.Split(attr.Val, ",")...)
						}
					}
				}
			}
		}

		// Check script content
		if n.Data == "script" {
			if n.FirstChild != nil {
				scriptContent := n.FirstChild.Data
				for _, pattern := range sensitivePatterns {
					if strings.Contains(scriptContent, pattern) {
						keywords = append(keywords, "Script contains: "+pattern)
					}
				}
			}
		}

	case html.CommentNode:
		// Check HTML comments for sensitive information
		comment := strings.ToLower(n.Data)
		if strings.Contains(comment, "todo") {
			keywords = append(keywords, "Comment: TODO found")
		}
		if strings.Contains(comment, "flag:") {
			keywords = append(keywords, "Comment: Possible flag")
		}
		for _, pattern := range sensitivePatterns {
			if strings.Contains(comment, strings.ToLower(pattern)) {
				keywords = append(keywords, "Comment contains: "+pattern)
			}
		}

	case html.TextNode:
		// Check text content for sensitive patterns
		text := strings.ToLower(n.Data)
		for _, pattern := range sensitivePatterns {
			if strings.Contains(text, strings.ToLower(pattern)) {
				keywords = append(keywords, "Content contains: "+pattern)
			}
		}
	}

	// Recursively check child nodes
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		keywords = append(keywords, extractKeywords(c)...)
	}

	return keywords
}
