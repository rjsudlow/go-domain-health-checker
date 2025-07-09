package checker

import (
	"fmt"
	"regexp"
	"strings"
)

// GetDMARCRecord retrieves and analyzes DMARC records for a domain
func (c *Checker) GetDMARCRecord(domain string) (*DMARCResult, error) {
	if err := ValidateDomain(domain); err != nil {
		return nil, fmt.Errorf("invalid domain: %w", err)
	}

	dmarcDomain := fmt.Sprintf("_dmarc.%s", domain)
	dmarcRecords, err := c.dns.LookupTXT(dmarcDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup DMARC record: %w", err)
	}

	var dmarcRecord string
	var dmarcAdvisory string

	// Find DMARC record
	for _, record := range dmarcRecords {
		if strings.HasPrefix(strings.TrimSpace(record), "v=DMARC1") {
			dmarcRecord = record
			break
		}
	}

	if dmarcRecord == "" {
		dmarcAdvisory = "Does not have a DMARC record. This domain is at risk to being abused by phishers and spammers."
		return &DMARCResult{
			Name:          domain,
			DMARCRecord:   "",
			DMARCAdvisory: dmarcAdvisory,
		}, nil
	}

	// Analyze DMARC policy
	dmarcAdvisory = c.analyzeDMARCPolicy(dmarcRecord)

	return &DMARCResult{
		Name:          domain,
		DMARCRecord:   dmarcRecord,
		DMARCAdvisory: dmarcAdvisory,
	}, nil
}

// analyzeDMARCPolicy analyzes DMARC policy and returns advisory message
func (c *Checker) analyzeDMARCPolicy(dmarcRecord string) string {
	var advisory string

	// Check main policy (p=)
	if policyMatch := regexp.MustCompile(`p=([^;]+)`).FindStringSubmatch(dmarcRecord); len(policyMatch) > 1 {
		policy := strings.TrimSpace(policyMatch[1])
		switch policy {
		case "none":
			advisory = "Domain has a valid DMARC record but the DMARC policy does not prevent abuse of your domain by phishers and spammers."
		case "quarantine":
			advisory = "Domain has a DMARC record and it is set to p=quarantine. To fully take advantage of DMARC, the policy should be set to p=reject."
		case "reject":
			advisory = "Domain has a DMARC record and your DMARC policy will prevent abuse of your domain by phishers and spammers. "
		default:
			advisory = "Domain has a DMARC record but the policy is not recognized. Valid policies are: none, quarantine, reject."
		}
	}

	// Check subdomain policy (sp=)
	if spolicyMatch := regexp.MustCompile(`sp=([^;]+)`).FindStringSubmatch(dmarcRecord); len(spolicyMatch) > 1 {
		spolicy := strings.TrimSpace(spolicyMatch[1])
		switch spolicy {
		case "none":
			advisory += "The subdomain policy does not prevent abuse of your domain by phishers and spammers."
		case "quarantine":
			advisory += "The subdomain has a DMARC record and it is set to sp=quarantine. To prevent you subdomains configure the policy to sp=reject."
		case "reject":
			advisory += "The subdomain policy prevent abuse of your domain by phishers and spammers."
		}
	}

	return advisory
}

// ValidateDMARCRecord performs comprehensive DMARC record validation
func ValidateDMARCRecord(dmarcRecord string) []string {
	var issues []string

	if dmarcRecord == "" {
		issues = append(issues, "DMARC record is empty")
		return issues
	}

	// Check if record starts with v=DMARC1
	if !strings.HasPrefix(strings.TrimSpace(dmarcRecord), "v=DMARC1") {
		issues = append(issues, "DMARC record must start with 'v=DMARC1'")
	}

	// Parse DMARC record parameters
	params := parseDMARCParameters(dmarcRecord)

	// Check required policy parameter
	if policy, exists := params["p"]; exists {
		if policy != "none" && policy != "quarantine" && policy != "reject" {
			issues = append(issues, fmt.Sprintf("Invalid policy value: %s (must be none, quarantine, or reject)", policy))
		}
	} else {
		issues = append(issues, "DMARC record missing required policy parameter (p=)")
	}

	// Validate optional subdomain policy
	if spolicy, exists := params["sp"]; exists {
		if spolicy != "none" && spolicy != "quarantine" && spolicy != "reject" {
			issues = append(issues, fmt.Sprintf("Invalid subdomain policy value: %s (must be none, quarantine, or reject)", spolicy))
		}
	}

	// Validate alignment modes
	if aspfAlign, exists := params["aspf"]; exists {
		if aspfAlign != "r" && aspfAlign != "s" {
			issues = append(issues, fmt.Sprintf("Invalid SPF alignment mode: %s (must be r or s)", aspfAlign))
		}
	}

	if adkimAlign, exists := params["adkim"]; exists {
		if adkimAlign != "r" && adkimAlign != "s" {
			issues = append(issues, fmt.Sprintf("Invalid DKIM alignment mode: %s (must be r or s)", adkimAlign))
		}
	}

	// Validate percentage
	if pct, exists := params["pct"]; exists {
		if !isValidPercentage(pct) {
			issues = append(issues, fmt.Sprintf("Invalid percentage value: %s (must be 0-100)", pct))
		}
	}

	// Validate report interval
	if ri, exists := params["ri"]; exists {
		if !isValidReportInterval(ri) {
			issues = append(issues, fmt.Sprintf("Invalid report interval: %s (must be a positive integer)", ri))
		}
	}

	// Validate failure reporting options
	if fo, exists := params["fo"]; exists {
		if !isValidFailureOptions(fo) {
			issues = append(issues, fmt.Sprintf("Invalid failure reporting options: %s", fo))
		}
	}

	// Validate report URIs
	if rua, exists := params["rua"]; exists {
		if !isValidReportURI(rua) {
			issues = append(issues, fmt.Sprintf("Invalid aggregate report URI: %s", rua))
		}
	}

	if ruf, exists := params["ruf"]; exists {
		if !isValidReportURI(ruf) {
			issues = append(issues, fmt.Sprintf("Invalid failure report URI: %s", ruf))
		}
	}

	return issues
}

// parseDMARCParameters parses DMARC record parameters into a map
func parseDMARCParameters(dmarcRecord string) map[string]string {
	params := make(map[string]string)

	// Split by semicolon and process each parameter
	parts := strings.Split(dmarcRecord, ";")
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

// isValidPercentage checks if a string represents a valid percentage (0-100)
func isValidPercentage(pct string) bool {
	percentageRegex := regexp.MustCompile(`^(100|[1-9]?\d)$`)
	return percentageRegex.MatchString(pct)
}

// isValidReportInterval checks if a string represents a valid report interval
func isValidReportInterval(ri string) bool {
	intervalRegex := regexp.MustCompile(`^\d+$`)
	return intervalRegex.MatchString(ri)
}

// isValidFailureOptions checks if failure reporting options are valid
func isValidFailureOptions(fo string) bool {
	// Valid options are combinations of 0, 1, d, s
	validOptions := regexp.MustCompile(`^[01ds:]+$`)
	return validOptions.MatchString(fo)
}

// isValidReportURI checks if a report URI is valid
func isValidReportURI(uri string) bool {
	// Basic URI validation - should contain mailto: or https://
	uris := strings.Split(uri, ",")
	for _, u := range uris {
		u = strings.TrimSpace(u)
		if !strings.HasPrefix(u, "mailto:") && !strings.HasPrefix(u, "https://") {
			return false
		}
	}
	return true
}

// GetDMARCPolicyInfo extracts policy information from DMARC record
func GetDMARCPolicyInfo(dmarcRecord string) map[string]interface{} {
	params := parseDMARCParameters(dmarcRecord)
	policyInfo := make(map[string]interface{})

	// Extract policy information
	if version, exists := params["v"]; exists {
		policyInfo["version"] = version
	}

	if policy, exists := params["p"]; exists {
		policyInfo["policy"] = policy
	}

	if spolicy, exists := params["sp"]; exists {
		policyInfo["subdomain_policy"] = spolicy
	}

	if aspf, exists := params["aspf"]; exists {
		policyInfo["spf_alignment"] = aspf
	} else {
		policyInfo["spf_alignment"] = "r" // Default
	}

	if adkim, exists := params["adkim"]; exists {
		policyInfo["dkim_alignment"] = adkim
	} else {
		policyInfo["dkim_alignment"] = "r" // Default
	}

	if pct, exists := params["pct"]; exists {
		policyInfo["percentage"] = pct
	} else {
		policyInfo["percentage"] = "100" // Default
	}

	if ri, exists := params["ri"]; exists {
		policyInfo["report_interval"] = ri
	} else {
		policyInfo["report_interval"] = "86400" // Default (24 hours)
	}

	if fo, exists := params["fo"]; exists {
		policyInfo["failure_options"] = fo
	} else {
		policyInfo["failure_options"] = "0" // Default
	}

	if rua, exists := params["rua"]; exists {
		policyInfo["aggregate_report_uri"] = rua
	}

	if ruf, exists := params["ruf"]; exists {
		policyInfo["failure_report_uri"] = ruf
	}

	return policyInfo
}

// GetDMARCRecommendations returns recommendations for DMARC implementation
func GetDMARCRecommendations(dmarcRecord string) []string {
	recommendations := []string{}
	params := parseDMARCParameters(dmarcRecord)

	// Policy recommendations
	if policy, exists := params["p"]; exists {
		switch policy {
		case "none":
			recommendations = append(recommendations, "Consider upgrading policy from 'none' to 'quarantine' or 'reject' for better protection")
		case "quarantine":
			recommendations = append(recommendations, "Consider upgrading policy from 'quarantine' to 'reject' for maximum protection")
		}
	}

	// Percentage recommendations
	if pct, exists := params["pct"]; exists && pct != "100" {
		recommendations = append(recommendations, "Consider setting pct=100 for full policy enforcement")
	}

	// Alignment recommendations
	if aspf, exists := params["aspf"]; exists && aspf == "r" {
		recommendations = append(recommendations, "Consider using strict SPF alignment (aspf=s) for enhanced security")
	}

	if adkim, exists := params["adkim"]; exists && adkim == "r" {
		recommendations = append(recommendations, "Consider using strict DKIM alignment (adkim=s) for enhanced security")
	}

	// Reporting recommendations
	if _, exists := params["rua"]; !exists {
		recommendations = append(recommendations, "Add aggregate report URI (rua=) to monitor DMARC compliance")
	}

	if _, exists := params["ruf"]; !exists {
		recommendations = append(recommendations, "Consider adding failure report URI (ruf=) for detailed failure analysis")
	}

	return recommendations
}

// AnalyzeDMARCImplementation provides analysis of DMARC implementation maturity
func AnalyzeDMARCImplementation(dmarcRecord string) map[string]interface{} {
	analysis := make(map[string]interface{})
	params := parseDMARCParameters(dmarcRecord)

	// Determine implementation maturity
	maturityScore := 0
	maturityFactors := []string{}

	if policy, exists := params["p"]; exists {
		switch policy {
		case "none":
			maturityScore += 1
			maturityFactors = append(maturityFactors, "Monitoring phase (p=none)")
		case "quarantine":
			maturityScore += 2
			maturityFactors = append(maturityFactors, "Enforcement phase (p=quarantine)")
		case "reject":
			maturityScore += 3
			maturityFactors = append(maturityFactors, "Full protection (p=reject)")
		}
	}

	if pct, exists := params["pct"]; exists && pct == "100" {
		maturityScore += 1
		maturityFactors = append(maturityFactors, "Full percentage enforcement")
	}

	if _, exists := params["rua"]; exists {
		maturityScore += 1
		maturityFactors = append(maturityFactors, "Aggregate reporting configured")
	}

	if aspf, exists := params["aspf"]; exists && aspf == "s" {
		maturityScore += 1
		maturityFactors = append(maturityFactors, "Strict SPF alignment")
	}

	if adkim, exists := params["adkim"]; exists && adkim == "s" {
		maturityScore += 1
		maturityFactors = append(maturityFactors, "Strict DKIM alignment")
	}

	// Determine maturity level
	var maturityLevel string
	switch {
	case maturityScore >= 6:
		maturityLevel = "Advanced"
	case maturityScore >= 4:
		maturityLevel = "Intermediate"
	case maturityScore >= 2:
		maturityLevel = "Basic"
	default:
		maturityLevel = "Initial"
	}

	analysis["maturity_level"] = maturityLevel
	analysis["maturity_score"] = maturityScore
	analysis["maturity_factors"] = maturityFactors

	return analysis
}
