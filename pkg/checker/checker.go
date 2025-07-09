package checker

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Checker is the main struct that orchestrates domain health checks
type Checker struct {
	dns     *DNSClient
	options CheckOptions
}

// New creates a new Checker instance with the specified options
func New(options CheckOptions) *Checker {
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}

	dnsClient := NewDNSClient(options.Server, options.Timeout)

	return &Checker{
		dns:     dnsClient,
		options: options,
	}
}

// CheckDomain performs a comprehensive health check for a single domain
func (c *Checker) CheckDomain(domain string) (*DomainHealthResult, error) {
	start := time.Now()

	if err := ValidateDomain(domain); err != nil {
		return nil, fmt.Errorf("invalid domain: %w", err)
	}

	result := &DomainHealthResult{
		Name:           domain,
		CheckTimestamp: start,
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var errors []error

	// SPF Check
	wg.Add(1)
	go func() {
		defer wg.Done()
		spfResult, err := c.GetSPFRecord(domain)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errors = append(errors, fmt.Errorf("SPF check failed: %w", err))
		} else {
			result.SPFRecord = spfResult.SPFRecord
			result.SPFAdvisory = spfResult.SPFAdvisory
			result.SPFRecordLength = spfResult.SPFRecordLength
			result.SPFRecordDNSLookupCount = FormatSPFDNSLookupCount(spfResult.SPFRecordDNSLookupCount)
		}
	}()

	// DKIM Check
	wg.Add(1)
	go func() {
		defer wg.Done()
		dkimResult, err := c.GetDKIMRecord(domain, c.options.DKIMSelector)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errors = append(errors, fmt.Errorf("DKIM check failed: %w", err))
		} else {
			result.DKIMRecord = dkimResult.DKIMRecord
			result.DKIMSelector = dkimResult.DKIMSelector
			result.DKIMAdvisory = dkimResult.DKIMAdvisory
		}
	}()

	// DMARC Check
	wg.Add(1)
	go func() {
		defer wg.Done()
		dmarcResult, err := c.GetDMARCRecord(domain)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errors = append(errors, fmt.Errorf("DMARC check failed: %w", err))
		} else {
			result.DMARCRecord = dmarcResult.DMARCRecord
			result.DMARCAdvisory = dmarcResult.DMARCAdvisory
		}
	}()

	// MTA-STS Check
	wg.Add(1)
	go func() {
		defer wg.Done()
		mtaResult, err := c.GetMTASTSRecord(domain)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errors = append(errors, fmt.Errorf("MTA-STS check failed: %w", err))
		} else {
			result.MTARecord = mtaResult.MTARecord
			result.MTAAdvisory = mtaResult.MTAAdvisory
		}
	}()

	// DNSSEC Check (optional)
	if c.options.IncludeDNSSEC {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dnssecResult, err := c.GetDNSSECRecord(domain)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errors = append(errors, fmt.Errorf("DNSSEC check failed: %w", err))
			} else {
				result.DNSSEC = dnssecResult.DNSSEC
				result.DNSSECAdvisory = dnssecResult.DNSSECAdvisory
			}
		}()
	}

	// Wait for all checks to complete
	wg.Wait()

	// Calculate duration
	duration := time.Since(start)
	result.CheckDurationMs = duration.Nanoseconds() / 1000000

	// Return first error if any occurred
	if len(errors) > 0 {
		return result, errors[0]
	}

	return result, nil
}

// CheckDomains performs health checks for multiple domains
func (c *Checker) CheckDomains(domains []string) ([]*DomainHealthResult, []error) {
	results := make([]*DomainHealthResult, len(domains))
	errors := make([]error, len(domains))

	if c.options.Concurrent {
		// Concurrent processing
		var wg sync.WaitGroup
		for i, domain := range domains {
			wg.Add(1)
			go func(index int, dom string) {
				defer wg.Done()
				result, err := c.CheckDomain(dom)
				results[index] = result
				errors[index] = err
			}(i, domain)
		}
		wg.Wait()
	} else {
		// Sequential processing
		for i, domain := range domains {
			result, err := c.CheckDomain(domain)
			results[i] = result
			errors[i] = err
		}
	}

	// Filter out nil errors
	var filteredErrors []error
	for _, err := range errors {
		if err != nil {
			filteredErrors = append(filteredErrors, err)
		}
	}

	return results, filteredErrors
}

// CheckDomainsFromFile reads domains from a file and performs health checks
func (c *Checker) CheckDomainsFromFile(filePath string) ([]*DomainHealthResult, []error) {
	domains, err := ReadDomainsFromFile(filePath)
	if err != nil {
		return nil, []error{fmt.Errorf("failed to read domains from file: %w", err)}
	}

	return c.CheckDomains(domains)
}

// GetSummary returns a summary of domain health results
func GetSummary(results []*DomainHealthResult) *HealthSummary {
	summary := &HealthSummary{
		TotalDomains: len(results),
		Summary:      make(map[string]int),
	}

	for _, result := range results {
		// SPF Analysis
		if result.SPFRecord != "" {
			summary.SPFConfigured++
			if containsStrict(result.SPFAdvisory, "sufficiently strict") {
				summary.SPFStrict++
			}
		}

		// DKIM Analysis
		if result.DKIMRecord != "" {
			summary.DKIMConfigured++
		}

		// DMARC Analysis
		if result.DMARCRecord != "" {
			summary.DMARCConfigured++
			if containsStrict(result.DMARCAdvisory, "p=reject") {
				summary.DMARCReject++
			}
		}

		// MTA-STS Analysis
		if result.MTARecord != "" {
			summary.MTASTSConfigured++
		}

		// DNSSEC Analysis
		if result.DNSSEC != "" && containsStrict(result.DNSSEC, "DNSSEC signed") {
			summary.DNSSECEnabled++
		}
	}

	// Calculate percentages
	if summary.TotalDomains > 0 {
		summary.SPFPercentage = float64(summary.SPFConfigured) / float64(summary.TotalDomains) * 100
		summary.DKIMPercentage = float64(summary.DKIMConfigured) / float64(summary.TotalDomains) * 100
		summary.DMARCPercentage = float64(summary.DMARCConfigured) / float64(summary.TotalDomains) * 100
		summary.MTASTSPercentage = float64(summary.MTASTSConfigured) / float64(summary.TotalDomains) * 100
		summary.DNSSECPercentage = float64(summary.DNSSECEnabled) / float64(summary.TotalDomains) * 100
	}

	return summary
}

// HealthSummary provides aggregate statistics for domain health checks
type HealthSummary struct {
	TotalDomains     int            `json:"total_domains"`
	SPFConfigured    int            `json:"spf_configured"`
	SPFStrict        int            `json:"spf_strict"`
	SPFPercentage    float64        `json:"spf_percentage"`
	DKIMConfigured   int            `json:"dkim_configured"`
	DKIMPercentage   float64        `json:"dkim_percentage"`
	DMARCConfigured  int            `json:"dmarc_configured"`
	DMARCReject      int            `json:"dmarc_reject"`
	DMARCPercentage  float64        `json:"dmarc_percentage"`
	MTASTSConfigured int            `json:"mtasts_configured"`
	MTASTSPercentage float64        `json:"mtasts_percentage"`
	DNSSECEnabled    int            `json:"dnssec_enabled"`
	DNSSECPercentage float64        `json:"dnssec_percentage"`
	Summary          map[string]int `json:"summary"`
}

// containsStrict checks if a string contains another string (case-insensitive)
func containsStrict(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

// SetDNSServer updates the DNS server for the checker
func (c *Checker) SetDNSServer(server string) {
	c.dns = NewDNSClient(server, c.options.Timeout)
	c.options.Server = server
}

// SetTimeout updates the timeout for DNS queries
func (c *Checker) SetTimeout(timeout time.Duration) {
	c.options.Timeout = timeout
	c.dns = NewDNSClient(c.options.Server, timeout)
}

// GetOptions returns the current checker options
func (c *Checker) GetOptions() CheckOptions {
	return c.options
}

// Validate performs a quick validation check on the checker configuration
func (c *Checker) Validate() error {
	if c.dns == nil {
		return fmt.Errorf("DNS client is not initialized")
	}

	if c.options.Timeout <= 0 {
		return fmt.Errorf("timeout must be greater than 0")
	}

	return nil
}
