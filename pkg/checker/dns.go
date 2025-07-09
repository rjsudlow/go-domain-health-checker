package checker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSClient handles DNS queries with optional custom server support
type DNSClient struct {
	server  string
	timeout time.Duration
	client  *dns.Client
}

// NewDNSClient creates a new DNS client with optional custom server
func NewDNSClient(server string, timeout time.Duration) *DNSClient {
	client := &dns.Client{
		Timeout: timeout,
	}

	return &DNSClient{
		server:  server,
		timeout: timeout,
		client:  client,
	}
}

// LookupTXT performs TXT record lookup with custom server support
func (d *DNSClient) LookupTXT(domain string) ([]string, error) {
	if d.server == "" {
		// Use standard library for default DNS
		return net.LookupTXT(domain)
	}

	// Use custom DNS server
	return d.queryTXT(domain)
}

// LookupMX performs MX record lookup with custom server support
func (d *DNSClient) LookupMX(domain string) ([]*net.MX, error) {
	if d.server == "" {
		// Use standard library for default DNS
		return net.LookupMX(domain)
	}

	// Use custom DNS server
	return d.queryMX(domain)
}

// LookupCNAME performs CNAME record lookup with custom server support
func (d *DNSClient) LookupCNAME(domain string) (string, error) {
	if d.server == "" {
		// Use standard library for default DNS
		return net.LookupCNAME(domain)
	}

	// Use custom DNS server
	return d.queryCNAME(domain)
}

// LookupDNSKEY performs DNSKEY record lookup (always uses miekg/dns)
func (d *DNSClient) LookupDNSKEY(domain string) ([]dns.DNSKEY, error) {
	return d.queryDNSKEY(domain)
}

// queryTXT performs TXT record query using miekg/dns
func (d *DNSClient) queryTXT(domain string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)

	server := d.server
	if !strings.Contains(server, ":") {
		server = server + ":53"
	}

	r, _, err := d.client.Exchange(m, server)
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %w", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query failed with rcode: %d", r.Rcode)
	}

	var txtRecords []string
	for _, ans := range r.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			txtRecords = append(txtRecords, strings.Join(txt.Txt, ""))
		}
	}

	return txtRecords, nil
}

// queryMX performs MX record query using miekg/dns
func (d *DNSClient) queryMX(domain string) ([]*net.MX, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)

	server := d.server
	if !strings.Contains(server, ":") {
		server = server + ":53"
	}

	r, _, err := d.client.Exchange(m, server)
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %w", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query failed with rcode: %d", r.Rcode)
	}

	var mxRecords []*net.MX
	for _, ans := range r.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			mxRecords = append(mxRecords, &net.MX{
				Host: strings.TrimSuffix(mx.Mx, "."),
				Pref: mx.Preference,
			})
		}
	}

	return mxRecords, nil
}

// queryCNAME performs CNAME record query using miekg/dns
func (d *DNSClient) queryCNAME(domain string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCNAME)

	server := d.server
	if !strings.Contains(server, ":") {
		server = server + ":53"
	}

	r, _, err := d.client.Exchange(m, server)
	if err != nil {
		return "", fmt.Errorf("DNS query failed: %w", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("DNS query failed with rcode: %d", r.Rcode)
	}

	for _, ans := range r.Answer {
		if cname, ok := ans.(*dns.CNAME); ok {
			return strings.TrimSuffix(cname.Target, "."), nil
		}
	}

	return "", fmt.Errorf("no CNAME record found")
}

// queryDNSKEY performs DNSKEY record query using miekg/dns
func (d *DNSClient) queryDNSKEY(domain string) ([]dns.DNSKEY, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)

	server := d.server
	if server == "" {
		server = "8.8.8.8:53" // Default to Google DNS for DNSSEC queries
	}
	if !strings.Contains(server, ":") {
		server = server + ":53"
	}

	r, _, err := d.client.Exchange(m, server)
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %w", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query failed with rcode: %d", r.Rcode)
	}

	var dnskeyRecords []dns.DNSKEY
	for _, ans := range r.Answer {
		if dnskey, ok := ans.(*dns.DNSKEY); ok {
			dnskeyRecords = append(dnskeyRecords, *dnskey)
		}
	}

	return dnskeyRecords, nil
}

// ResolveTXTWithFilter performs TXT lookup and filters results by pattern
func (d *DNSClient) ResolveTXTWithFilter(domain, pattern string) ([]string, error) {
	txtRecords, err := d.LookupTXT(domain)
	if err != nil {
		return nil, err
	}

	var filtered []string
	for _, record := range txtRecords {
		if strings.Contains(record, pattern) {
			filtered = append(filtered, record)
		}
	}

	return filtered, nil
}

// FollowCNAMEChain follows CNAME records until a TXT record is found
func (d *DNSClient) FollowCNAMEChain(domain string) ([]string, error) {
	currentDomain := domain
	maxHops := 10 // Prevent infinite loops

	for i := 0; i < maxHops; i++ {
		// First try to get TXT records
		txtRecords, err := d.LookupTXT(currentDomain)
		if err == nil && len(txtRecords) > 0 {
			return txtRecords, nil
		}

		// If no TXT records, check for CNAME
		cname, err := d.LookupCNAME(currentDomain)
		if err != nil {
			// No CNAME found, return original error or empty result
			return nil, fmt.Errorf("no TXT records found for %s", domain)
		}

		currentDomain = cname
	}

	return nil, fmt.Errorf("CNAME chain too long for %s", domain)
}

// ValidateDomain performs basic domain validation
func ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}

	if len(domain) > 253 {
		return fmt.Errorf("domain too long")
	}

	// Basic domain format validation
	if strings.Contains(domain, "..") {
		return fmt.Errorf("invalid domain format")
	}

	return nil
}

// WithTimeout creates a context with timeout for DNS operations
func WithTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}
