package checker

import (
	"fmt"
	"strings"
)

// GetDKIMRecord retrieves and analyzes DKIM records for a domain
func (c *Checker) GetDKIMRecord(domain string, customSelector string) (*DKIMResult, error) {
	if err := ValidateDomain(domain); err != nil {
		return nil, fmt.Errorf("invalid domain: %w", err)
	}

	var dkimRecord string
	var dkimSelector string
	var dkimAdvisory string

	if customSelector != "" {
		// Use custom selector
		dkimRecord, dkimSelector, dkimAdvisory = c.checkDKIMSelector(domain, customSelector)
	} else {
		// Try common selectors
		dkimRecord, dkimSelector, dkimAdvisory = c.bruteForceDKIMSelectors(domain)
	}

	return &DKIMResult{
		Name:         domain,
		DKIMRecord:   dkimRecord,
		DKIMSelector: dkimSelector,
		DKIMAdvisory: dkimAdvisory,
	}, nil
}

// checkDKIMSelector checks a specific DKIM selector for a domain
func (c *Checker) checkDKIMSelector(domain, selector string) (string, string, string) {
	dkimDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)

	// First try TXT record lookup
	txtRecords, err := c.dns.LookupTXT(dkimDomain)
	if err == nil && len(txtRecords) > 0 {
		for _, record := range txtRecords {
			if c.isValidDKIMRecord(record) {
				return record, selector, "DKIM-record found."
			}
		}
	}

	// If TXT lookup fails, try following CNAME chain
	cnameRecords, err := c.dns.FollowCNAMEChain(dkimDomain)
	if err == nil && len(cnameRecords) > 0 {
		for _, record := range cnameRecords {
			if c.isValidDKIMRecord(record) {
				return record, selector, "DKIM-record found."
			}
		}
	}

	return "", selector, fmt.Sprintf("No DKIM-record found for selector %s._domainkey.%s", selector, domain)
}

// bruteForceDKIMSelectors tries common DKIM selectors to find valid records
func (c *Checker) bruteForceDKIMSelectors(domain string) (string, string, string) {
	for _, selector := range DKIMSelectors {
		dkimRecord, _, advisory := c.checkDKIMSelector(domain, selector)
		if dkimRecord != "" && c.isValidDKIMRecord(dkimRecord) {
			return dkimRecord, selector, advisory
		}
	}

	return "", "", "We couldn't find a DKIM record associated with your domain."
}

// isValidDKIMRecord checks if a record is a valid DKIM record
func (c *Checker) isValidDKIMRecord(record string) bool {
	// DKIM records should contain either v=DKIM1 or at least have a key parameter
	return strings.Contains(record, "v=DKIM1") || strings.Contains(record, "k=")
}

// ValidateDKIMRecord performs comprehensive DKIM record validation
func ValidateDKIMRecord(dkimRecord string) []string {
	var issues []string

	if dkimRecord == "" {
		issues = append(issues, "DKIM record is empty")
		return issues
	}

	// Parse DKIM record parameters
	params := parseDKIMParameters(dkimRecord)

	// Check version
	if version, exists := params["v"]; exists {
		if version != "DKIM1" {
			issues = append(issues, fmt.Sprintf("Invalid DKIM version: %s (should be DKIM1)", version))
		}
	} else {
		issues = append(issues, "DKIM record missing version parameter (v=)")
	}

	// Check key type
	if keyType, exists := params["k"]; exists {
		if keyType != "rsa" && keyType != "ed25519" {
			issues = append(issues, fmt.Sprintf("Unsupported key type: %s", keyType))
		}
	}

	// Check hash algorithms
	if hashAlg, exists := params["h"]; exists {
		validAlgorithms := []string{"sha1", "sha256"}
		algorithms := strings.Split(hashAlg, ":")
		for _, alg := range algorithms {
			if !contains(validAlgorithms, strings.TrimSpace(alg)) {
				issues = append(issues, fmt.Sprintf("Invalid hash algorithm: %s", alg))
			}
		}
	}

	// Check service type
	if serviceType, exists := params["s"]; exists {
		if serviceType != "*" && serviceType != "email" {
			issues = append(issues, fmt.Sprintf("Invalid service type: %s", serviceType))
		}
	}

	// Check flags
	if flags, exists := params["t"]; exists {
		validFlags := []string{"y", "s"}
		flagList := strings.Split(flags, ":")
		for _, flag := range flagList {
			if !contains(validFlags, strings.TrimSpace(flag)) {
				issues = append(issues, fmt.Sprintf("Invalid flag: %s", flag))
			}
		}
	}

	// Check if public key exists
	if publicKey, exists := params["p"]; exists {
		if publicKey == "" {
			issues = append(issues, "Public key is empty (revoked key)")
		}
	} else {
		issues = append(issues, "DKIM record missing public key parameter (p=)")
	}

	return issues
}

// parseDKIMParameters parses DKIM record parameters into a map
func parseDKIMParameters(dkimRecord string) map[string]string {
	params := make(map[string]string)

	// Split by semicolon and process each parameter
	parts := strings.Split(dkimRecord, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Split by equals sign
		if equalIndex := strings.Index(part, "="); equalIndex != -1 {
			key := strings.TrimSpace(part[:equalIndex])
			value := strings.TrimSpace(part[equalIndex+1:])
			params[key] = value
		}
	}

	return params
}

// GetDKIMKeyInfo extracts key information from DKIM record
func GetDKIMKeyInfo(dkimRecord string) map[string]interface{} {
	params := parseDKIMParameters(dkimRecord)
	keyInfo := make(map[string]interface{})

	// Extract key information
	if version, exists := params["v"]; exists {
		keyInfo["version"] = version
	}

	if keyType, exists := params["k"]; exists {
		keyInfo["key_type"] = keyType
	} else {
		keyInfo["key_type"] = "rsa" // Default
	}

	if hashAlg, exists := params["h"]; exists {
		keyInfo["hash_algorithms"] = strings.Split(hashAlg, ":")
	}

	if serviceType, exists := params["s"]; exists {
		keyInfo["service_type"] = serviceType
	} else {
		keyInfo["service_type"] = "*" // Default
	}

	if flags, exists := params["t"]; exists {
		keyInfo["flags"] = strings.Split(flags, ":")
	}

	if publicKey, exists := params["p"]; exists {
		keyInfo["public_key"] = publicKey
		keyInfo["key_revoked"] = publicKey == ""
	}

	if notes, exists := params["n"]; exists {
		keyInfo["notes"] = notes
	}

	return keyInfo
}

// contains checks if a slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// GetDKIMSelectorRecommendations returns recommendations for DKIM selector usage
func GetDKIMSelectorRecommendations(domain string) []string {
	recommendations := []string{
		"Use descriptive selector names that indicate the service or date",
		"Rotate DKIM keys regularly (every 6-12 months)",
		"Use multiple selectors for key rotation without service interruption",
		"Keep selector names short but meaningful",
		"Consider using date-based selectors (e.g., 2024jan, 2024jul)",
	}

	return recommendations
}

// AnalyzeDKIMStrength analyzes the strength of a DKIM configuration
func AnalyzeDKIMStrength(dkimRecord string) map[string]interface{} {
	analysis := make(map[string]interface{})
	params := parseDKIMParameters(dkimRecord)

	// Check key length for RSA keys
	if keyType, exists := params["k"]; !exists || keyType == "rsa" {
		if publicKey, exists := params["p"]; exists && publicKey != "" {
			// Estimate key length based on base64 encoded public key length
			// This is an approximation
			keyLength := estimateRSAKeyLength(publicKey)
			analysis["estimated_key_length"] = keyLength

			if keyLength < 1024 {
				analysis["key_strength"] = "weak"
				analysis["key_recommendation"] = "Use at least 1024-bit RSA keys, 2048-bit recommended"
			} else if keyLength < 2048 {
				analysis["key_strength"] = "acceptable"
				analysis["key_recommendation"] = "Consider upgrading to 2048-bit RSA keys"
			} else {
				analysis["key_strength"] = "strong"
				analysis["key_recommendation"] = "Key length is adequate"
			}
		}
	}

	// Check hash algorithms
	if hashAlg, exists := params["h"]; exists {
		algorithms := strings.Split(hashAlg, ":")
		hasStrong := false
		hasWeak := false

		for _, alg := range algorithms {
			alg = strings.TrimSpace(alg)
			if alg == "sha256" {
				hasStrong = true
			} else if alg == "sha1" {
				hasWeak = true
			}
		}

		if hasStrong && !hasWeak {
			analysis["hash_strength"] = "strong"
			analysis["hash_recommendation"] = "Using strong hash algorithms"
		} else if hasStrong && hasWeak {
			analysis["hash_strength"] = "mixed"
			analysis["hash_recommendation"] = "Remove SHA-1 support, use only SHA-256"
		} else if hasWeak {
			analysis["hash_strength"] = "weak"
			analysis["hash_recommendation"] = "Upgrade to SHA-256, SHA-1 is deprecated"
		}
	}

	// Check for testing flag
	if flags, exists := params["t"]; exists {
		if strings.Contains(flags, "y") {
			analysis["testing_mode"] = true
			analysis["testing_recommendation"] = "Remove testing flag (t=y) in production"
		}
	}

	return analysis
}

// estimateRSAKeyLength estimates RSA key length from base64 encoded public key
func estimateRSAKeyLength(publicKey string) int {
	// This is a rough estimation based on typical base64 encoded key lengths
	keyLen := len(publicKey)

	switch {
	case keyLen < 200:
		return 1024
	case keyLen < 400:
		return 2048
	case keyLen < 600:
		return 3072
	default:
		return 4096
	}
}
