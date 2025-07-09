package checker

import "time"

// DomainHealthResult represents the complete health check result for a domain
type DomainHealthResult struct {
	Name                    string    `json:"name"`
	SPFRecord               string    `json:"spf_record"`
	SPFAdvisory             string    `json:"spf_advisory"`
	SPFRecordLength         int       `json:"spf_record_length"`
	SPFRecordDNSLookupCount string    `json:"spf_record_dns_lookup_count"`
	DMARCRecord             string    `json:"dmarc_record"`
	DMARCAdvisory           string    `json:"dmarc_advisory"`
	DKIMRecord              string    `json:"dkim_record"`
	DKIMSelector            string    `json:"dkim_selector"`
	DKIMAdvisory            string    `json:"dkim_advisory"`
	MTARecord               string    `json:"mta_record"`
	MTAAdvisory             string    `json:"mta_advisory"`
	DNSSEC                  string    `json:"dnssec,omitempty"`
	DNSSECAdvisory          string    `json:"dnssec_advisory,omitempty"`
	CheckTimestamp          time.Time `json:"check_timestamp"`
	CheckDurationMs         int64     `json:"check_duration_ms"`
}

// SPFResult represents SPF record analysis results
type SPFResult struct {
	Name                    string `json:"name"`
	SPFRecord               string `json:"spf_record"`
	SPFRecordLength         int    `json:"spf_record_length"`
	SPFRecordDNSLookupCount int    `json:"spf_record_dns_lookup_count"`
	SPFAdvisory             string `json:"spf_advisory"`
}

// DKIMResult represents DKIM record analysis results
type DKIMResult struct {
	Name         string `json:"name"`
	DKIMRecord   string `json:"dkim_record"`
	DKIMSelector string `json:"dkim_selector"`
	DKIMAdvisory string `json:"dkim_advisory"`
}

// DMARCResult represents DMARC record analysis results
type DMARCResult struct {
	Name          string `json:"name"`
	DMARCRecord   string `json:"dmarc_record"`
	DMARCAdvisory string `json:"dmarc_advisory"`
}

// DNSSECResult represents DNSSEC analysis results
type DNSSECResult struct {
	Name           string `json:"name"`
	DNSSEC         string `json:"dnssec"`
	DNSSECAdvisory string `json:"dnssec_advisory"`
}

// MTASTSResult represents MTA-STS analysis results
type MTASTSResult struct {
	Name        string `json:"name"`
	MTARecord   string `json:"mta_record"`
	MTAAdvisory string `json:"mta_advisory"`
}

// CheckOptions represents configuration options for domain health checks
type CheckOptions struct {
	Domain        string
	DKIMSelector  string
	Server        string
	IncludeDNSSEC bool
	Timeout       time.Duration
	Concurrent    bool
}

// Common DKIM selectors based on the PowerShell implementation
var DKIMSelectors = []string{
	"selector1",     // Microsoft
	"selector2",     // Microsoft
	"google",        // Google Workspace
	"everlytickey1", // Everlytic
	"everlytickey2", // Everlytic
	"eversrv",       // Everlytic OLD selector
	"k1",            // Mailchimp / Mandrill
	"k2",            // Mailchimp / Mandrill
	"mxvault",       // Global Micro
	"dkim",          // Hetzner
	"s1",            // Sendgrid / NationBulder
	"s2",            // Sendgrid / NationBuilder
	"ctct1",         // Constant Contact
	"ctct2",         // Constant Contact
	"sm",            // Blackbaud, eTapestry
	"sig1",          // iCloud
	"litesrv",       // MailerLite
	"zendesk1",      // Zendesk
	"zendesk2",      // Zendesk
}

// Error types for different failure scenarios
type CheckError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Domain  string `json:"domain"`
}

func (e CheckError) Error() string {
	return e.Message
}

// DNS lookup result for internal use
type DNSLookupResult struct {
	Records []string
	Error   error
}
