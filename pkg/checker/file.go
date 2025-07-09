package checker

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ReadDomainsFromFile reads domain names from a file, one per line
func ReadDomainsFromFile(filePath string) ([]string, error) {
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", filePath)
	}

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Basic domain validation
		if err := ValidateDomain(line); err != nil {
			return nil, fmt.Errorf("invalid domain at line %d: %s - %w", lineNumber, line, err)
		}

		domains = append(domains, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	if len(domains) == 0 {
		return nil, fmt.Errorf("no valid domains found in file: %s", filePath)
	}

	return domains, nil
}

// WriteDomainsToFile writes domain names to a file, one per line
func WriteDomainsToFile(filePath string, domains []string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Create or truncate the file
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for _, domain := range domains {
		if _, err := writer.WriteString(domain + "\n"); err != nil {
			return fmt.Errorf("failed to write domain to file: %w", err)
		}
	}

	return nil
}

// ReadDomainsFromCSV reads domain names from a CSV file
func ReadDomainsFromCSV(filePath string, columnIndex int) ([]string, error) {
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", filePath)
	}

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse CSV line
		fields := strings.Split(line, ",")
		if len(fields) <= columnIndex {
			return nil, fmt.Errorf("line %d does not have enough columns (expected at least %d)", lineNumber, columnIndex+1)
		}

		domain := strings.TrimSpace(fields[columnIndex])
		if domain == "" {
			continue
		}

		// Basic domain validation
		if err := ValidateDomain(domain); err != nil {
			return nil, fmt.Errorf("invalid domain at line %d: %s - %w", lineNumber, domain, err)
		}

		domains = append(domains, domain)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	if len(domains) == 0 {
		return nil, fmt.Errorf("no valid domains found in file: %s", filePath)
	}

	return domains, nil
}

// AppendDomainsToFile appends domain names to an existing file
func AppendDomainsToFile(filePath string, domains []string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Open file for appending
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file for appending: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for _, domain := range domains {
		if _, err := writer.WriteString(domain + "\n"); err != nil {
			return fmt.Errorf("failed to write domain to file: %w", err)
		}
	}

	return nil
}

// RemoveDuplicatesFromFile removes duplicate domain names from a file
func RemoveDuplicatesFromFile(filePath string) error {
	domains, err := ReadDomainsFromFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read domains from file: %w", err)
	}

	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueDomains []string

	for _, domain := range domains {
		if !seen[domain] {
			seen[domain] = true
			uniqueDomains = append(uniqueDomains, domain)
		}
	}

	// Write back unique domains
	return WriteDomainsToFile(filePath, uniqueDomains)
}

// ValidateFileFormat checks if a file has the expected format
func ValidateFileFormat(filePath string) error {
	// Check file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	validExtensions := []string{".txt", ".csv", ".list", ".domains"}

	isValidExt := false
	for _, validExt := range validExtensions {
		if ext == validExt {
			isValidExt = true
			break
		}
	}

	if !isValidExt {
		return fmt.Errorf("unsupported file extension: %s (supported: %s)", ext, strings.Join(validExtensions, ", "))
	}

	// Check if file is readable
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", filePath)
	}

	// Try to read at least one line
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return fmt.Errorf("file is empty or cannot be read: %s", filePath)
	}

	return nil
}

// GetFileInfo returns information about a domain file
func GetFileInfo(filePath string) (*FileInfo, error) {
	stat, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	domains, err := ReadDomainsFromFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read domains: %w", err)
	}

	info := &FileInfo{
		Path:        filePath,
		Size:        stat.Size(),
		ModTime:     stat.ModTime(),
		DomainCount: len(domains),
		FirstDomain: "",
		LastDomain:  "",
	}

	if len(domains) > 0 {
		info.FirstDomain = domains[0]
		info.LastDomain = domains[len(domains)-1]
	}

	return info, nil
}

// FileInfo contains information about a domain file
type FileInfo struct {
	Path        string    `json:"path"`
	Size        int64     `json:"size"`
	ModTime     time.Time `json:"mod_time"`
	DomainCount int       `json:"domain_count"`
	FirstDomain string    `json:"first_domain"`
	LastDomain  string    `json:"last_domain"`
}

// CreateSampleFile creates a sample domain file for testing
func CreateSampleFile(filePath string) error {
	sampleDomains := []string{
		"example.com",
		"google.com",
		"microsoft.com",
		"amazon.com",
		"facebook.com",
		"twitter.com",
		"linkedin.com",
		"github.com",
		"stackoverflow.com",
		"reddit.com",
	}

	return WriteDomainsToFile(filePath, sampleDomains)
}
