# Go Domain Health Checker

A comprehensive, cross-platform domain health checker for email security records, written in Go. This tool analyzes SPF, DKIM, DMARC, DNSSEC, and MTA-STS records to help you secure your email infrastructure.

This is a Go reimplementation of the PowerShell [Invoke-SpfDkimDmarc](https://github.com/T13nn3s/Show-SpfDkimDmarc) module, providing enhanced performance, cross-platform compatibility, and native DNS resolution capabilities.

## Features

- **Complete Email Security Analysis**: SPF, DKIM, DMARC, DNSSEC, and MTA-STS record validation
- **Cross-Platform**: Works on Windows, Linux, macOS, and other Unix-like systems
- **High Performance**: Native Go implementation with concurrent processing support
- **Flexible Input**: Single domain, multiple domains, or file-based input
- **Custom DNS Servers**: Support for custom DNS servers (e.g., 8.8.8.8, 1.1.1.1)
- **Multiple Output Formats**: Table, JSON, and CSV output
- **DKIM Selector Brute Force**: Automatically tests common DKIM selectors
- **Comprehensive Validation**: Detailed record validation with actionable recommendations
- **No Dependencies**: Single binary with no external dependencies

## Supported Record Types

### SPF (Sender Policy Framework)
- Record existence and syntax validation
- DNS lookup count analysis (RFC 7208 compliance)
- Policy strength assessment
- Redirect mechanism support
- Length validation

### DKIM (DomainKeys Identified Mail)
- Automatic selector discovery using common selectors
- Custom selector support
- CNAME chain following
- Key strength analysis
- Algorithm validation

### DMARC (Domain-based Message Authentication, Reporting, and Conformance)
- Policy analysis (none, quarantine, reject)
- Subdomain policy validation
- Alignment mode checking
- Reporting configuration analysis
- Implementation maturity assessment

### DNSSEC (DNS Security Extensions)
- DNSKEY record validation
- DS record checking
- Algorithm strength analysis
- Chain of trust validation

### MTA-STS (Mail Transfer Agent Strict Transport Security)
- DNS record validation
- Policy file retrieval and analysis
- MX record comparison
- TLS support verification
- Mode enforcement checking

## Installation

### Download Pre-built Binary

Download the latest binary from the [releases page](https://github.com/your-org/go-domain-health-checker/releases).

### Build from Source

```bash
git clone https://github.com/rjsudlow/go-domain-health-checker.git
cd go-domain-health-checker
go build -o domain-health-checker cmd/main.go
```

### Using Go Install

```bash
go install github.com/your-org/go-domain-health-checker/cmd@latest
```

## Usage

### Basic Usage

Check a single domain:
```bash
./domain-health-checker check example.com
```

Check multiple domains:
```bash
./domain-health-checker check example.com google.com microsoft.com
```

Check domains from a file:
```bash
./domain-health-checker check --file domains.txt
```

### Advanced Usage

Use custom DNS server:
```bash
./domain-health-checker check --dns-server 8.8.8.8 example.com
```

Include DNSSEC validation:
```bash
./domain-health-checker check --include-dnssec example.com
```

Use custom DKIM selector:
```bash
./domain-health-checker check --dkim-selector custom-selector example.com
```

Process domains concurrently:
```bash
./domain-health-checker check --concurrent --file domains.txt
```

Output as JSON:
```bash
./domain-health-checker check --output json example.com
```

Save results to file:
```bash
./domain-health-checker check --output json --output-file results.json example.com
```

### Individual Record Checks

Check only SPF records:
```bash
./domain-health-checker spf example.com
```

Check only DKIM records:
```bash
./domain-health-checker dkim example.com
```

Check only DMARC records:
```bash
./domain-health-checker dmarc example.com
```

Check only DNSSEC:
```bash
./domain-health-checker dnssec example.com
```

Check only MTA-STS:
```bash
./domain-health-checker mta-sts example.com
```

### Generate Summary Report

```bash
./domain-health-checker summary --file domains.txt
```

### Validate Records Offline

Validate SPF record syntax:
```bash
./domain-health-checker validate spf "v=spf1 include:_spf.google.com ~all"
```

Validate DMARC record:
```bash
./domain-health-checker validate dmarc "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
```

## Command Line Options

### Global Flags

- `--dns-server`: Custom DNS server to use (e.g., 8.8.8.8, 1.1.1.1)
- `--timeout`: Timeout for DNS queries (default: 30s)
- `--output`: Output format (table, json, csv)
- `--output-file`: Output file path
- `--concurrent`: Process domains concurrently
- `--verbose`: Enable verbose output

### Check Command Flags

- `--file`: File containing domains to check (one per line)
- `--dkim-selector`: Custom DKIM selector
- `--include-dnssec`: Include DNSSEC validation
- `--csv-column`: Column index for CSV files (0-based)

## File Formats

### Domain List File

Create a text file with one domain per line:

```
example.com
google.com
microsoft.com
# This is a comment
amazon.com
```

### CSV File

Use CSV files with domain names in a specific column:

```csv
Company,Domain,Contact
Example Inc,example.com,admin@example.com
Google,google.com,security@google.com
Microsoft,microsoft.com,security@microsoft.com
```

Then use:
```bash
./domain-health-checker check --file domains.csv --csv-column 1
```

## Output Formats

### Table Output (Default)

```
Domain               SPF        DKIM       DMARC      MTA-STS    DNSSEC
--------------------------------------------------------------------------------
example.com          ✓          ✓          ✓          ✗          ✗
google.com           ✓          ✓          ✓          ✓          ✓
microsoft.com        ✓          ✓          ✓          ✗          ✗
```

### JSON Output

```json
[
  {
    "name": "example.com",
    "spf_record": "v=spf1 include:_spf.google.com ~all",
    "spf_advisory": "An SPF-record is configured but the policy is not sufficiently strict.",
    "spf_record_length": 32,
    "spf_record_dns_lookup_count": "1/10 (OK)",
    "dmarc_record": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
    "dmarc_advisory": "Domain has a valid DMARC record but the DMARC policy does not prevent abuse.",
    "dkim_record": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...",
    "dkim_selector": "selector1",
    "dkim_advisory": "DKIM-record found.",
    "mta_record": "",
    "mta_advisory": "The MTA-STS DNS record doesn't exist.",
    "check_timestamp": "2024-01-15T10:30:00Z",
    "check_duration_ms": 1250
  }
]
```

### CSV Output

```csv
Domain,SPF Record,SPF Advisory,DKIM Record,DKIM Advisory,DMARC Record,DMARC Advisory,MTA-STS Record,MTA-STS Advisory,DNSSEC,DNSSEC Advisory
example.com,"v=spf1 include:_spf.google.com ~all","An SPF-record is configured but the policy is not sufficiently strict.","v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...","DKIM-record found.","v=DMARC1; p=none; rua=mailto:dmarc@example.com","Domain has a valid DMARC record but the DMARC policy does not prevent abuse.","","The MTA-STS DNS record doesn't exist.","","Enable DNSSEC on your domain. DNSSEC decreases the vulnerability to DNS attacks."
```

## Examples

### Basic Domain Check

```bash
./domain-health-checker check example.com
```

Expected output:
```
Domain               SPF        DKIM       DMARC      MTA-STS    DNSSEC
--------------------------------------------------------------------------------
example.com          ✓          ✓          ✓          ✗          ✗
```

### Comprehensive Security Audit

```bash
./domain-health-checker check --include-dnssec --output json --output-file audit.json --concurrent --file company-domains.txt
```

### Quick SPF Check

```bash
./domain-health-checker spf example.com
```

### Batch Processing with Custom DNS

```bash
./domain-health-checker check --dns-server 1.1.1.1 --concurrent --file domains.txt --output csv --output-file results.csv
```

## Common DKIM Selectors

The tool automatically tests these common DKIM selectors:

- `selector1`, `selector2` (Microsoft)
- `google` (Google Workspace)
- `k1`, `k2` (Mailchimp/Mandrill)
- `s1`, `s2` (SendGrid)
- `dkim` (Hetzner)
- `everlytickey1`, `everlytickey2` (Everlytic)
- `sig1` (iCloud)
- `zendesk1`, `zendesk2` (Zendesk)
- And many more...

## Performance

- **Concurrent Processing**: Enable with `--concurrent` flag for faster bulk checks
- **DNS Caching**: Efficient DNS resolution with connection reuse
- **Timeout Control**: Configurable timeouts to prevent hanging on slow DNS servers
- **Resource Efficient**: Low memory footprint even with large domain lists

## API Usage

You can also use the checker as a Go library:

```go
package main

import (
    "fmt"
    "time"
    "github.com/domain-health-checker/pkg/checker"
)

func main() {
    options := checker.CheckOptions{
        Server:        "8.8.8.8",
        Timeout:       30 * time.Second,
        IncludeDNSSEC: true,
        Concurrent:    true,
    }
    
    c := checker.New(options)
    
    result, err := c.CheckDomain("example.com")
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("SPF: %s\n", result.SPFRecord)
    fmt.Printf("DKIM: %s\n", result.DKIMRecord)
    fmt.Printf("DMARC: %s\n", result.DMARCRecord)
}
```

## Troubleshooting

### DNS Resolution Issues

If you encounter DNS resolution problems:

1. Try using a different DNS server:
   ```bash
   ./domain-health-checker check --dns-server 8.8.8.8 example.com
   ```

2. Increase timeout:
   ```bash
   ./domain-health-checker check --timeout 60s example.com
   ```

3. Enable verbose output:
   ```bash
   ./domain-health-checker check --verbose example.com
   ```

### Common Error Messages

- **"no such host"**: Domain doesn't exist or DNS resolution failed
- **"timeout"**: DNS query timed out (try increasing timeout or changing DNS server)
- **"connection refused"**: DNS server is not responding
- **"invalid domain"**: Domain name format is incorrect

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Original PowerShell implementation by [T13nn3s](https://github.com/T13nn3s/Show-SpfDkimDmarc)
- DNS library by [Miek Gieben](https://github.com/miekg/dns)
- CLI framework by [Cobra](https://github.com/spf13/cobra)

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/your-org/go-domain-health-checker).
