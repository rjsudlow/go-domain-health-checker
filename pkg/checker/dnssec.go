package checker

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// GetDNSSECRecord checks if a domain has DNSSEC enabled
func (c *Checker) GetDNSSECRecord(domain string) (*DNSSECResult, error) {
	if err := ValidateDomain(domain); err != nil {
		return nil, fmt.Errorf("invalid domain: %w", err)
	}

	dnskeyRecords, err := c.dns.LookupDNSKEY(domain)
	if err != nil {
		return &DNSSECResult{
			Name:           domain,
			DNSSEC:         "No DNSKEY records found.",
			DNSSECAdvisory: "Enable DNSSEC on your domain. DNSSEC decreases the vulnerability to DNS attacks.",
		}, nil
	}

	var dnssecStatus string
	var dnssecAdvisory string

	if len(dnskeyRecords) > 0 {
		// Check if any of the records are actually DNSKEY records
		hasDNSKEY := false
		for _, record := range dnskeyRecords {
			if record.Hdr.Rrtype == dns.TypeDNSKEY {
				hasDNSKEY = true
				break
			}
		}

		if hasDNSKEY {
			dnssecStatus = "Domain is DNSSEC signed."
			dnssecAdvisory = "Great! DNSSEC is enabled on your domain."
		} else {
			dnssecStatus = "No DNSKEY records found."
			dnssecAdvisory = "Enable DNSSEC on your domain. DNSSEC decreases the vulnerability to DNS attacks."
		}
	} else {
		dnssecStatus = "No DNSKEY records found."
		dnssecAdvisory = "Enable DNSSEC on your domain. DNSSEC decreases the vulnerability to DNS attacks."
	}

	return &DNSSECResult{
		Name:           domain,
		DNSSEC:         dnssecStatus,
		DNSSECAdvisory: dnssecAdvisory,
	}, nil
}

// ValidateDNSSECChain validates the DNSSEC chain of trust for a domain
func (c *Checker) ValidateDNSSECChain(domain string) (*DNSSECValidationResult, error) {
	if err := ValidateDomain(domain); err != nil {
		return nil, fmt.Errorf("invalid domain: %w", err)
	}

	result := &DNSSECValidationResult{
		Domain:     domain,
		IsValid:    false,
		ChainSteps: []DNSSECChainStep{},
	}

	// Check DNSKEY records
	dnskeyRecords, err := c.dns.LookupDNSKEY(domain)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to lookup DNSKEY records: %v", err)
		return result, nil
	}

	if len(dnskeyRecords) == 0 {
		result.Error = "No DNSKEY records found"
		return result, nil
	}

	// Analyze DNSKEY records
	for _, record := range dnskeyRecords {
		step := DNSSECChainStep{
			Type:        "DNSKEY",
			Name:        domain,
			Algorithm:   getDNSKEYAlgorithmName(record.Algorithm),
			KeyTag:      int(record.KeyTag()),
			Flags:       record.Flags,
			IsValid:     true,
			Description: fmt.Sprintf("DNSKEY record found with algorithm %s", getDNSKEYAlgorithmName(record.Algorithm)),
		}

		// Check if it's a KSK (Key Signing Key) or ZSK (Zone Signing Key)
		if record.Flags&256 != 0 {
			step.KeyType = "ZSK"
			step.Description += " (Zone Signing Key)"
		}
		if record.Flags&257 == 257 {
			step.KeyType = "KSK"
			step.Description += " (Key Signing Key)"
		}

		result.ChainSteps = append(result.ChainSteps, step)
	}

	// Check for DS records in parent zone
	dsRecords, err := c.checkDSRecords(domain)
	if err == nil && len(dsRecords) > 0 {
		for _, dsRecord := range dsRecords {
			step := DNSSECChainStep{
				Type:        "DS",
				Name:        getParentDomain(domain),
				Algorithm:   getDSAlgorithmName(dsRecord.Algorithm),
				KeyTag:      int(dsRecord.KeyTag),
				IsValid:     true,
				Description: fmt.Sprintf("DS record found in parent zone with algorithm %s", getDSAlgorithmName(dsRecord.Algorithm)),
			}
			result.ChainSteps = append(result.ChainSteps, step)
		}
		result.IsValid = true
	}

	return result, nil
}

// checkDSRecords checks for DS records in the parent zone
func (c *Checker) checkDSRecords(domain string) ([]dns.DS, error) {
	parentDomain := getParentDomain(domain)
	if parentDomain == "" {
		return nil, fmt.Errorf("no parent domain found")
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDS)

	server := c.dns.server
	if server == "" {
		server = "8.8.8.8:53"
	}
	if !strings.Contains(server, ":") {
		server = server + ":53"
	}

	r, _, err := c.dns.client.Exchange(m, server)
	if err != nil {
		return nil, fmt.Errorf("DS query failed: %w", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DS query failed with rcode: %d", r.Rcode)
	}

	var dsRecords []dns.DS
	for _, ans := range r.Answer {
		if ds, ok := ans.(*dns.DS); ok {
			dsRecords = append(dsRecords, *ds)
		}
	}

	return dsRecords, nil
}

// getParentDomain returns the parent domain of a given domain
func getParentDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return "" // No parent domain for TLD or root
	}
	return strings.Join(parts[1:], ".")
}

// getDNSKEYAlgorithmName returns the algorithm name for a DNSKEY algorithm number
func getDNSKEYAlgorithmName(algorithm uint8) string {
	algorithms := map[uint8]string{
		1:  "RSAMD5",
		3:  "DSA",
		5:  "RSASHA1",
		6:  "DSA-NSEC3-SHA1",
		7:  "RSASHA1-NSEC3-SHA1",
		8:  "RSASHA256",
		10: "RSASHA512",
		12: "ECC-GOST",
		13: "ECDSAP256SHA256",
		14: "ECDSAP384SHA384",
		15: "ED25519",
		16: "ED448",
	}

	if name, exists := algorithms[algorithm]; exists {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", algorithm)
}

// getDSAlgorithmName returns the algorithm name for a DS algorithm number
func getDSAlgorithmName(algorithm uint8) string {
	algorithms := map[uint8]string{
		1: "SHA-1",
		2: "SHA-256",
		3: "GOST",
		4: "SHA-384",
	}

	if name, exists := algorithms[algorithm]; exists {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", algorithm)
}

// GetDNSSECAlgorithmStrength analyzes the strength of DNSSEC algorithms used
func GetDNSSECAlgorithmStrength(dnskeyRecords []dns.DNSKEY) map[string]interface{} {
	analysis := make(map[string]interface{})

	algorithmCounts := make(map[string]int)
	var weakAlgorithms []string
	var strongAlgorithms []string

	for _, record := range dnskeyRecords {
		algorithmName := getDNSKEYAlgorithmName(record.Algorithm)
		algorithmCounts[algorithmName]++

		// Categorize algorithm strength
		switch record.Algorithm {
		case 1, 3, 5, 6, 7: // Older algorithms
			weakAlgorithms = append(weakAlgorithms, algorithmName)
		case 8, 10, 13, 14, 15, 16: // Modern algorithms
			strongAlgorithms = append(strongAlgorithms, algorithmName)
		}
	}

	analysis["algorithm_counts"] = algorithmCounts
	analysis["weak_algorithms"] = weakAlgorithms
	analysis["strong_algorithms"] = strongAlgorithms

	// Overall strength assessment
	if len(strongAlgorithms) > 0 && len(weakAlgorithms) == 0 {
		analysis["overall_strength"] = "strong"
		analysis["recommendation"] = "Using modern DNSSEC algorithms"
	} else if len(strongAlgorithms) > 0 && len(weakAlgorithms) > 0 {
		analysis["overall_strength"] = "mixed"
		analysis["recommendation"] = "Consider upgrading weak algorithms to modern ones"
	} else {
		analysis["overall_strength"] = "weak"
		analysis["recommendation"] = "Upgrade to modern DNSSEC algorithms (RSASHA256, RSASHA512, or ECDSA)"
	}

	return analysis
}

// DNSSECValidationResult represents the result of DNSSEC chain validation
type DNSSECValidationResult struct {
	Domain     string            `json:"domain"`
	IsValid    bool              `json:"is_valid"`
	ChainSteps []DNSSECChainStep `json:"chain_steps"`
	Error      string            `json:"error,omitempty"`
}

// DNSSECChainStep represents a step in the DNSSEC chain of trust
type DNSSECChainStep struct {
	Type        string `json:"type"`        // DNSKEY, DS, RRSIG
	Name        string `json:"name"`        // Domain name
	Algorithm   string `json:"algorithm"`   // Algorithm name
	KeyTag      int    `json:"key_tag"`     // Key tag
	KeyType     string `json:"key_type"`    // KSK, ZSK
	Flags       uint16 `json:"flags"`       // DNSKEY flags
	IsValid     bool   `json:"is_valid"`    // Whether this step is valid
	Description string `json:"description"` // Human readable description
}

// GetDNSSECRecommendations returns recommendations for DNSSEC implementation
func GetDNSSECRecommendations(domain string, hasRecords bool) []string {
	recommendations := []string{}

	if !hasRecords {
		recommendations = append(recommendations, "Enable DNSSEC on your domain to protect against DNS spoofing attacks")
		recommendations = append(recommendations, "Contact your DNS provider to enable DNSSEC signing")
		recommendations = append(recommendations, "Ensure your registrar supports DS record submission")
	} else {
		recommendations = append(recommendations, "Regularly monitor DNSSEC validation status")
		recommendations = append(recommendations, "Plan for key rollover procedures")
		recommendations = append(recommendations, "Monitor DS record propagation in parent zone")
		recommendations = append(recommendations, "Consider using modern algorithms (RSASHA256, ECDSA)")
	}

	return recommendations
}

// CheckDNSSECValidation performs a comprehensive DNSSEC validation check
func (c *Checker) CheckDNSSECValidation(domain string) (*DNSSECValidationResult, error) {
	validation, err := c.ValidateDNSSECChain(domain)
	if err != nil {
		return nil, err
	}

	// Additional validation checks
	if validation.IsValid {
		// Check if validation actually works by querying with DO bit
		if err := c.validateWithDOBit(domain); err != nil {
			validation.IsValid = false
			validation.Error = fmt.Sprintf("DNSSEC validation failed: %v", err)
		}
	}

	return validation, nil
}

// validateWithDOBit validates DNSSEC by querying with the DO (DNSSEC OK) bit set
func (c *Checker) validateWithDOBit(domain string) error {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.SetEdns0(4096, true) // Set DO bit

	server := c.dns.server
	if server == "" {
		server = "8.8.8.8:53"
	}
	if !strings.Contains(server, ":") {
		server = server + ":53"
	}

	r, _, err := c.dns.client.Exchange(m, server)
	if err != nil {
		return fmt.Errorf("DNSSEC validation query failed: %w", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNSSEC validation failed with rcode: %d", r.Rcode)
	}

	// Check for RRSIG records in the response
	hasRRSIG := false
	for _, ans := range r.Answer {
		if ans.Header().Rrtype == dns.TypeRRSIG {
			hasRRSIG = true
			break
		}
	}

	if !hasRRSIG {
		return fmt.Errorf("no RRSIG records found in response")
	}

	return nil
}
