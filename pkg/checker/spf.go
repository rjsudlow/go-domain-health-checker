package checker

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// GetSPFRecord retrieves and analyzes SPF records for a domain
func (c *Checker) GetSPFRecord(domain string) (*SPFResult, error) {
	if err := ValidateDomain(domain); err != nil {
		return nil, fmt.Errorf("invalid domain: %w", err)
	}

	// Get SPF record from specified domain
	spfRecords, err := c.dns.ResolveTXTWithFilter(domain, "v=spf1")
	if err != nil {
		return nil, fmt.Errorf("failed to lookup SPF record: %w", err)
	}

	var spfRecord string
	var spfAdvisory string

	// Check for SPF redirect and follow the redirect
	if len(spfRecords) > 0 {
		spfRecord = spfRecords[0]
		if strings.Contains(spfRecord, "redirect") {
			redirectDomain := extractRedirectDomain(spfRecord)
			if redirectDomain != "" {
				redirectRecords, err := c.dns.ResolveTXTWithFilter(redirectDomain, "v=spf1")
				if err == nil && len(redirectRecords) > 0 {
					spfRecord = redirectRecords[0]
				}
			}
		}
	}

	// Check for multiple SPF records
	spfCount := len(spfRecords)

	// If there is no SPF record
	if len(spfRecords) == 0 || spfRecord == "" {
		spfAdvisory = "Domain does not have an SPF record. To prevent abuse of this domain, please add an SPF record to it."
		return &SPFResult{
			Name:                    domain,
			SPFRecord:               "",
			SPFRecordLength:         0,
			SPFRecordDNSLookupCount: 0,
			SPFAdvisory:             spfAdvisory,
		}, nil
	}

	if spfCount > 1 {
		spfAdvisory = "Domain has more than one SPF record. Only one SPF record per domain is allowed. This is explicitly defined in RFC4408."
	}

	// Calculate SPF record length
	spfLength := len(spfRecord)

	// Check SPF record length constraints
	if spfLength >= 450 {
		// See: https://datatracker.ietf.org/doc/html/rfc7208#section-3.4
		spfAdvisory += "Your SPF-record has more than 450 characters. This SHOULD be avoided according to RFC7208. "
	} else if spfLength >= 255 {
		// See: https://datatracker.ietf.org/doc/html/rfc4408#section-3.1.3
		spfAdvisory = "Your SPF record has more than 255 characters in one string. This MUST not be done as explicitly defined in RFC4408. "
	}

	// Analyze SPF policy
	spfAdvisory += c.analyzeSPFPolicy(spfRecord)

	// Calculate DNS lookup count
	dnsLookupCount := c.calculateSPFDNSLookupCount(spfRecord)

	return &SPFResult{
		Name:                    domain,
		SPFRecord:               spfRecord,
		SPFRecordLength:         spfLength,
		SPFRecordDNSLookupCount: dnsLookupCount,
		SPFAdvisory:             spfAdvisory,
	}, nil
}

// analyzeSPFPolicy analyzes SPF policy and returns advisory message
func (c *Checker) analyzeSPFPolicy(spfRecord string) string {
	switch {
	case strings.Contains(spfRecord, "~all"):
		return "An SPF-record is configured but the policy is not sufficiently strict."
	case strings.Contains(spfRecord, "-all"):
		return "An SPF-record is configured and the policy is sufficiently strict."
	case strings.Contains(spfRecord, "?all"):
		return "Your domain has a valid SPF record but your policy is not effective enough."
	case strings.Contains(spfRecord, "+all"):
		return "Your domain has a valid SPF record but your policy is not effective enough."
	default:
		return "No qualifier found. Your domain has a SPF record but your policy is not effective enough."
	}
}

// calculateSPFDNSLookupCount calculates the number of DNS lookups required for SPF validation
func (c *Checker) calculateSPFDNSLookupCount(spfRecord string) int {
	dnsLookupCount := 0

	// Get the mechanisms that count towards the DNS lookup limit
	mechanisms := strings.Split(spfRecord, " ")

	for _, mechanism := range mechanisms {
		mechanism = strings.TrimSpace(mechanism)
		if mechanism == "" {
			continue
		}

		switch {
		case strings.HasPrefix(mechanism, "include:"):
			dnsLookupCount++
			includeDomain := strings.TrimPrefix(mechanism, "include:")
			dnsLookupCount += c.countNestedSPFLookups(includeDomain, 1)
		case strings.HasPrefix(mechanism, "a:"), mechanism == "a":
			dnsLookupCount++
		case strings.HasPrefix(mechanism, "mx:"), mechanism == "mx":
			dnsLookupCount++
		case mechanism == "ptr":
			dnsLookupCount++
		}
	}

	return dnsLookupCount
}

// countNestedSPFLookups counts DNS lookups in nested SPF records (with recursion limit)
func (c *Checker) countNestedSPFLookups(domain string, depth int) int {
	if depth > 2 { // Limit recursion depth to prevent infinite loops
		return 0
	}

	includedRecords, err := c.dns.ResolveTXTWithFilter(domain, "v=spf1")
	if err != nil || len(includedRecords) == 0 {
		return 0
	}

	nestedLookups := 0
	spfRecord := includedRecords[0]
	mechanisms := strings.Split(spfRecord, " ")

	for _, mechanism := range mechanisms {
		mechanism = strings.TrimSpace(mechanism)
		if mechanism == "" {
			continue
		}

		switch {
		case strings.HasPrefix(mechanism, "include:"):
			nestedLookups++
			nestedDomain := strings.TrimPrefix(mechanism, "include:")
			nestedLookups += c.countNestedSPFLookups(nestedDomain, depth+1)
		case strings.HasPrefix(mechanism, "a:"), mechanism == "a":
			nestedLookups++
		case strings.HasPrefix(mechanism, "mx:"), mechanism == "mx":
			nestedLookups++
		case mechanism == "ptr":
			nestedLookups++
		}
	}

	return nestedLookups
}

// extractRedirectDomain extracts the domain from SPF redirect mechanism
func extractRedirectDomain(spfRecord string) string {
	redirectRegex := regexp.MustCompile(`redirect=([^\s]+)`)
	matches := redirectRegex.FindStringSubmatch(spfRecord)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// FormatSPFDNSLookupCount formats the DNS lookup count with advisory message
func FormatSPFDNSLookupCount(count int) string {
	switch {
	case count == 10:
		return strconv.Itoa(count) + "/10 (Ok, but maximum DNS Lookups reached!)"
	case count > 10:
		return strconv.Itoa(count) + "/10 (EXCEEDED - This will cause SPF validation failures!)"
	case count > 8:
		return strconv.Itoa(count) + "/10 (Ok, but watch your DNS Lookups!)"
	default:
		return strconv.Itoa(count) + "/10 (OK)"
	}
}

// ValidateSPFRecord performs comprehensive SPF record validation
func ValidateSPFRecord(spfRecord string) []string {
	var issues []string

	if !strings.HasPrefix(spfRecord, "v=spf1") {
		issues = append(issues, "SPF record must start with 'v=spf1'")
	}

	if len(spfRecord) > 450 {
		issues = append(issues, "SPF record exceeds recommended length of 450 characters")
	}

	if len(spfRecord) > 255 {
		issues = append(issues, "SPF record exceeds maximum length of 255 characters")
	}

	// Check for valid mechanisms
	mechanisms := strings.Split(spfRecord, " ")
	hasAll := false

	for _, mechanism := range mechanisms {
		mechanism = strings.TrimSpace(mechanism)
		if mechanism == "" {
			continue
		}

		if strings.HasSuffix(mechanism, "all") {
			hasAll = true
		}

		if !isValidSPFMechanism(mechanism) {
			issues = append(issues, fmt.Sprintf("Invalid SPF mechanism: %s", mechanism))
		}
	}

	if !hasAll {
		issues = append(issues, "SPF record should end with an 'all' mechanism")
	}

	return issues
}

// isValidSPFMechanism checks if a mechanism is valid according to SPF specification
func isValidSPFMechanism(mechanism string) bool {
	// Remove qualifiers (+, -, ~, ?)
	if len(mechanism) > 0 && strings.ContainsRune("+-~?", rune(mechanism[0])) {
		mechanism = mechanism[1:]
	}

	validMechanisms := []string{
		"v=spf1", "all", "include:", "a", "a:", "mx", "mx:", "ptr", "ptr:", "ip4:", "ip6:", "exists:", "redirect=",
	}

	for _, valid := range validMechanisms {
		if mechanism == valid || strings.HasPrefix(mechanism, valid) {
			return true
		}
	}

	return false
}
