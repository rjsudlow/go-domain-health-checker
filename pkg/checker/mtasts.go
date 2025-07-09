package checker

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// GetMTASTSRecord retrieves and analyzes MTA-STS records for a domain
func (c *Checker) GetMTASTSRecord(domain string) (*MTASTSResult, error) {
	if err := ValidateDomain(domain); err != nil {
		return nil, fmt.Errorf("invalid domain: %w", err)
	}

	mtastsDomain := fmt.Sprintf("_mta-sts.%s", domain)

	// Get MTA-STS DNS record
	txtRecords, err := c.dns.LookupTXT(mtastsDomain)
	if err != nil {
		return &MTASTSResult{
			Name:        domain,
			MTARecord:   "",
			MTAAdvisory: "The MTA-STS DNS record doesn't exist. ",
		}, nil
	}

	var mtaRecord string
	for _, record := range txtRecords {
		if strings.Contains(record, "v=STSv1") {
			mtaRecord = record
			break
		}
	}

	if mtaRecord == "" {
		return &MTASTSResult{
			Name:        domain,
			MTARecord:   "",
			MTAAdvisory: "The MTA-STS DNS record doesn't exist. ",
		}, nil
	}

	// Analyze MTA-STS record and policy
	advisory := c.analyzeMTASTSRecord(domain, mtaRecord)

	return &MTASTSResult{
		Name:        domain,
		MTARecord:   mtaRecord,
		MTAAdvisory: advisory,
	}, nil
}

// analyzeMTASTSRecord analyzes MTA-STS DNS record and policy file
func (c *Checker) analyzeMTASTSRecord(domain, mtaRecord string) string {
	// Check for multiple MTA-STS records
	if strings.Count(mtaRecord, "v=STSv1") > 1 {
		return "There are multiple MTA-STS DNS records. "
	}

	// Check version
	if !strings.Contains(mtaRecord, "v=STSv1") {
		return "The MTA-STS version is not configured properly. Only STSv1 is supported. "
	}

	// Check ID format
	idRegex := regexp.MustCompile(`id=([^;\s]{1,32})(?:;|$)`)
	if !idRegex.MatchString(mtaRecord) {
		return "The MTA-STS id must be alphanumeric and no longer than 32 characters. "
	}

	// Fetch and analyze policy file
	policyURL := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", domain)
	policyContent, err := c.fetchMTASTSPolicy(policyURL)
	if err != nil {
		return "The MTA-STS file doesn't exist. "
	}

	return c.analyzeMTASTSPolicy(domain, policyContent)
}

// fetchMTASTSPolicy fetches the MTA-STS policy file
func (c *Checker) fetchMTASTSPolicy(url string) (string, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch MTA-STS policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("MTA-STS policy returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read MTA-STS policy: %w", err)
	}

	return string(body), nil
}

// analyzeMTASTSPolicy analyzes the MTA-STS policy file content
func (c *Checker) analyzeMTASTSPolicy(domain, policyContent string) string {
	lines := strings.Split(policyContent, "\n")

	// Check version
	if !c.containsLine(lines, `version:\s*STSv1`) {
		return "The MTA-STS version is not configured in the file. The only option is STSv1. "
	}

	// Check mode
	modeRegex := regexp.MustCompile(`mode:\s*(enforce|none|testing)`)
	var mode string
	for _, line := range lines {
		if matches := modeRegex.FindStringSubmatch(line); len(matches) > 1 {
			mode = matches[1]
			break
		}
	}

	if mode == "" {
		return "The MTA-STS mode is not configured in the file. Options are Enforce, Testing and None. "
	}

	if mode != "enforce" {
		return fmt.Sprintf("The MTA-STS file is configured in %s mode and not protecting interception or tampering. ",
			strings.Title(strings.ToLower(mode)))
	}

	// Check MX records
	mxLines := c.extractMXRecords(lines)
	if len(mxLines) == 0 {
		return "The MTA-STS file doesn't have any MX record configured. "
	}

	// Compare MX records with DNS
	if !c.validateMXRecords(domain, mxLines) {
		return "The MTA-STS file MX records don't match with the MX records configured in the domain. "
	}

	// Check TLS support on MX records
	if !c.validateMXTLSSupport(domain, mxLines) {
		return "At least one of the MX records configured in the MTA-STS file MX records list doesn't support TLS. "
	}

	// Check max_age
	maxAgeRegex := regexp.MustCompile(`max_age:\s*(\d+)`)
	var maxAge int
	for _, line := range lines {
		if matches := maxAgeRegex.FindStringSubmatch(line); len(matches) > 1 {
			fmt.Sscanf(matches[1], "%d", &maxAge)
			break
		}
	}

	if maxAge < 604800 || maxAge > 31557600 {
		return "The MTA-STS max age configured in the file should be greater than 604800 seconds and less than 31557600 seconds. "
	}

	return "The domain has the MTA-STS DNS record and file configured and protected against interception or tampering."
}

// containsLine checks if any line matches the given regex pattern
func (c *Checker) containsLine(lines []string, pattern string) bool {
	regex := regexp.MustCompile(pattern)
	for _, line := range lines {
		if regex.MatchString(line) {
			return true
		}
	}
	return false
}

// extractMXRecords extracts MX records from MTA-STS policy lines
func (c *Checker) extractMXRecords(lines []string) []string {
	var mxRecords []string
	mxRegex := regexp.MustCompile(`mx:\s*(.+)`)

	for _, line := range lines {
		if matches := mxRegex.FindStringSubmatch(line); len(matches) > 1 {
			mx := strings.TrimSpace(matches[1])
			mxRecords = append(mxRecords, mx)
		}
	}

	return mxRecords
}

// validateMXRecords compares MTA-STS MX records with actual DNS MX records
func (c *Checker) validateMXRecords(domain string, mtastsMXRecords []string) bool {
	// Get actual MX records from DNS
	mxRecords, err := c.dns.LookupMX(domain)
	if err != nil {
		return false
	}

	// Create a map of actual MX records
	actualMXMap := make(map[string]bool)
	for _, mx := range mxRecords {
		actualMXMap[mx.Host] = true
	}

	// Check if all MTA-STS MX records match actual MX records
	for _, mtastsMX := range mtastsMXRecords {
		// Handle wildcard matching
		if strings.HasPrefix(mtastsMX, "*.") {
			// Wildcard matching logic
			pattern := strings.TrimPrefix(mtastsMX, "*.")
			found := false
			for actualMX := range actualMXMap {
				if strings.HasSuffix(actualMX, "."+pattern) || actualMX == pattern {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		} else {
			// Exact matching
			if !actualMXMap[mtastsMX] {
				return false
			}
		}
	}

	return true
}

// validateMXTLSSupport checks if MX records support TLS
func (c *Checker) validateMXTLSSupport(domain string, mtastsMXRecords []string) bool {
	// Get actual MX records from DNS
	mxRecords, err := c.dns.LookupMX(domain)
	if err != nil {
		return false
	}

	// Test TLS support for each MX record
	for _, mx := range mxRecords {
		if !c.testMXTLS(mx.Host) {
			return false
		}
	}

	return true
}

// testMXTLS tests if an MX record supports TLS (STARTTLS)
func (c *Checker) testMXTLS(mxHostname string) bool {
	// Connect to SMTP port
	conn, err := net.DialTimeout("tcp", mxHostname+":25", 10*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Read initial greeting
	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)
	if err != nil {
		return false
	}

	// Send EHLO
	_, err = conn.Write([]byte("EHLO TestingTLS\r\n"))
	if err != nil {
		return false
	}

	// Read EHLO response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(buffer)
	if err != nil {
		return false
	}

	// Send STARTTLS
	_, err = conn.Write([]byte("STARTTLS\r\n"))
	if err != nil {
		return false
	}

	// Read STARTTLS response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		return false
	}

	// Check for 220 response (Ready to start TLS)
	response := string(buffer[:n])
	return strings.Contains(response, "220")
}

// ValidateMTASTSRecord performs comprehensive MTA-STS record validation
func ValidateMTASTSRecord(mtaRecord string) []string {
	var issues []string

	if mtaRecord == "" {
		issues = append(issues, "MTA-STS record is empty")
		return issues
	}

	// Check version
	if !strings.Contains(mtaRecord, "v=STSv1") {
		issues = append(issues, "MTA-STS record must contain 'v=STSv1'")
	}

	// Check ID format
	idRegex := regexp.MustCompile(`id=([^;\s]{1,32})(?:;|$)`)
	if !idRegex.MatchString(mtaRecord) {
		issues = append(issues, "MTA-STS id must be alphanumeric and no longer than 32 characters")
	}

	// Check for extra parameters
	validParams := []string{"v=STSv1", "id="}
	params := strings.Split(mtaRecord, ";")
	for _, param := range params {
		param = strings.TrimSpace(param)
		if param == "" {
			continue
		}

		isValid := false
		for _, validParam := range validParams {
			if strings.HasPrefix(param, validParam) {
				isValid = true
				break
			}
		}

		if !isValid {
			issues = append(issues, fmt.Sprintf("Invalid parameter: %s", param))
		}
	}

	return issues
}

// ValidateMTASTSPolicy performs comprehensive MTA-STS policy validation
func ValidateMTASTSPolicy(policyContent string) []string {
	var issues []string
	lines := strings.Split(policyContent, "\n")

	// Check version
	versionRegex := regexp.MustCompile(`version:\s*STSv1`)
	hasVersion := false
	for _, line := range lines {
		if versionRegex.MatchString(line) {
			hasVersion = true
			break
		}
	}
	if !hasVersion {
		issues = append(issues, "Policy must contain 'version: STSv1'")
	}

	// Check mode
	modeRegex := regexp.MustCompile(`mode:\s*(enforce|none|testing)`)
	hasMode := false
	for _, line := range lines {
		if modeRegex.MatchString(line) {
			hasMode = true
			break
		}
	}
	if !hasMode {
		issues = append(issues, "Policy must contain valid mode (enforce, testing, or none)")
	}

	// Check max_age
	maxAgeRegex := regexp.MustCompile(`max_age:\s*(\d+)`)
	hasMaxAge := false
	for _, line := range lines {
		if matches := maxAgeRegex.FindStringSubmatch(line); len(matches) > 1 {
			hasMaxAge = true
			var maxAge int
			fmt.Sscanf(matches[1], "%d", &maxAge)
			if maxAge < 604800 || maxAge > 31557600 {
				issues = append(issues, "max_age should be between 604800 and 31557600 seconds")
			}
			break
		}
	}
	if !hasMaxAge {
		issues = append(issues, "Policy must contain valid max_age")
	}

	// Check for at least one MX record
	mxRegex := regexp.MustCompile(`mx:\s*(.+)`)
	hasMX := false
	for _, line := range lines {
		if mxRegex.MatchString(line) {
			hasMX = true
			break
		}
	}
	if !hasMX {
		issues = append(issues, "Policy must contain at least one MX record")
	}

	return issues
}

// GetMTASTSRecommendations returns recommendations for MTA-STS implementation
func GetMTASTSRecommendations(domain string, hasRecord bool) []string {
	recommendations := []string{}

	if !hasRecord {
		recommendations = append(recommendations, "Implement MTA-STS to protect against SMTP downgrade attacks")
		recommendations = append(recommendations, "Create MTA-STS DNS record with proper ID")
		recommendations = append(recommendations, "Host MTA-STS policy file at https://mta-sts."+domain+"/.well-known/mta-sts.txt")
		recommendations = append(recommendations, "Ensure all MX records support TLS")
	} else {
		recommendations = append(recommendations, "Regularly update MTA-STS policy ID when making changes")
		recommendations = append(recommendations, "Monitor MTA-STS policy file accessibility")
		recommendations = append(recommendations, "Consider implementing TLS-RPT for reporting")
		recommendations = append(recommendations, "Test MTA-STS implementation with email security tools")
	}

	return recommendations
}
