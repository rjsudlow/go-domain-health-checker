package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/domain-health-checker/pkg/checker"
	"github.com/spf13/cobra"
)

var (
	// Global flags
	dnsServer     string
	timeout       time.Duration
	outputFormat  string
	outputFile    string
	concurrent    bool
	dkimSelector  string
	includeDNSSEC bool
	verbose       bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "domain-health-checker",
	Short: "A comprehensive domain health checker for email security records",
	Long: `Domain Health Checker is a comprehensive tool for analyzing email security
records including SPF, DKIM, DMARC, DNSSEC, and MTA-STS for one or more domains.

This tool is a Go implementation of the PowerShell DomainHealthChecker module,
providing cross-platform support and enhanced performance.`,
	Example: `  # Check a single domain
  domain-health-checker check example.com

  # Check multiple domains
  domain-health-checker check example.com google.com microsoft.com

  # Check domains from a file
  domain-health-checker check --file domains.txt

  # Use custom DNS server
  domain-health-checker check --dns-server 8.8.8.8 example.com

  # Include DNSSEC validation
  domain-health-checker check --include-dnssec example.com

  # Output as JSON
  domain-health-checker check --output json example.com`,
}

// checkCmd represents the check command
var checkCmd = &cobra.Command{
	Use:   "check [domain1] [domain2] ...",
	Short: "Check domain health for SPF, DKIM, DMARC, DNSSEC, and MTA-STS records",
	Long: `Check domain health by analyzing SPF, DKIM, DMARC, DNSSEC, and MTA-STS records.
You can check single or multiple domains, or read domains from a file.`,
	Args: cobra.MinimumNArgs(0),
	RunE: runCheck,
}

// spfCmd represents the spf command
var spfCmd = &cobra.Command{
	Use:   "spf [domain1] [domain2] ...",
	Short: "Check SPF records only",
	Long:  `Check SPF (Sender Policy Framework) records for one or more domains.`,
	Args:  cobra.MinimumNArgs(1),
	RunE:  runSPF,
}

// dkimCmd represents the dkim command
var dkimCmd = &cobra.Command{
	Use:   "dkim [domain1] [domain2] ...",
	Short: "Check DKIM records only",
	Long:  `Check DKIM (DomainKeys Identified Mail) records for one or more domains.`,
	Args:  cobra.MinimumNArgs(1),
	RunE:  runDKIM,
}

// dmarcCmd represents the dmarc command
var dmarcCmd = &cobra.Command{
	Use:   "dmarc [domain1] [domain2] ...",
	Short: "Check DMARC records only",
	Long:  `Check DMARC (Domain-based Message Authentication, Reporting, and Conformance) records for one or more domains.`,
	Args:  cobra.MinimumNArgs(1),
	RunE:  runDMARC,
}

// dnssecCmd represents the dnssec command
var dnssecCmd = &cobra.Command{
	Use:   "dnssec [domain1] [domain2] ...",
	Short: "Check DNSSEC records only",
	Long:  `Check DNSSEC (DNS Security Extensions) records for one or more domains.`,
	Args:  cobra.MinimumNArgs(1),
	RunE:  runDNSSEC,
}

// mtastsCmd represents the mta-sts command
var mtastsCmd = &cobra.Command{
	Use:   "mta-sts [domain1] [domain2] ...",
	Short: "Check MTA-STS records only",
	Long:  `Check MTA-STS (Mail Transfer Agent Strict Transport Security) records for one or more domains.`,
	Args:  cobra.MinimumNArgs(1),
	RunE:  runMTASTS,
}

// summaryCmd represents the summary command
var summaryCmd = &cobra.Command{
	Use:   "summary [domain1] [domain2] ...",
	Short: "Generate a summary report for multiple domains",
	Long:  `Generate a summary report showing aggregate statistics for multiple domains.`,
	Args:  cobra.MinimumNArgs(1),
	RunE:  runSummary,
}

// validateCmd represents the validate command
var validateCmd = &cobra.Command{
	Use:   "validate [record-type] [record-value]",
	Short: "Validate individual DNS records",
	Long:  `Validate individual DNS records without performing DNS lookups.`,
	Args:  cobra.ExactArgs(2),
	RunE:  runValidate,
}

var (
	domainsFile string
	csvColumn   int
)

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&dnsServer, "dns-server", "", "Custom DNS server to use (e.g., 8.8.8.8)")
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", 30*time.Second, "Timeout for DNS queries")
	rootCmd.PersistentFlags().StringVar(&outputFormat, "output", "table", "Output format (table, json, csv)")
	rootCmd.PersistentFlags().StringVar(&outputFile, "output-file", "", "Output file path")
	rootCmd.PersistentFlags().BoolVar(&concurrent, "concurrent", false, "Process domains concurrently")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Enable verbose output")

	// Check command flags
	checkCmd.Flags().StringVar(&domainsFile, "file", "", "File containing domains to check (one per line)")
	checkCmd.Flags().StringVar(&dkimSelector, "dkim-selector", "", "Custom DKIM selector")
	checkCmd.Flags().BoolVar(&includeDNSSEC, "include-dnssec", false, "Include DNSSEC validation")
	checkCmd.Flags().IntVar(&csvColumn, "csv-column", 0, "Column index for CSV files (0-based)")

	// DKIM command flags
	dkimCmd.Flags().StringVar(&dkimSelector, "dkim-selector", "", "Custom DKIM selector")

	// Summary command flags
	summaryCmd.Flags().StringVar(&domainsFile, "file", "", "File containing domains to check (one per line)")

	// Add subcommands
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(spfCmd)
	rootCmd.AddCommand(dkimCmd)
	rootCmd.AddCommand(dmarcCmd)
	rootCmd.AddCommand(dnssecCmd)
	rootCmd.AddCommand(mtastsCmd)
	rootCmd.AddCommand(summaryCmd)
	rootCmd.AddCommand(validateCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func createChecker() *checker.Checker {
	options := checker.CheckOptions{
		Server:        dnsServer,
		DKIMSelector:  dkimSelector,
		IncludeDNSSEC: includeDNSSEC,
		Timeout:       timeout,
		Concurrent:    concurrent,
	}

	return checker.New(options)
}

func getDomains(cmd *cobra.Command, args []string) ([]string, error) {
	if domainsFile != "" {
		if strings.HasSuffix(strings.ToLower(domainsFile), ".csv") {
			return checker.ReadDomainsFromCSV(domainsFile, csvColumn)
		}
		return checker.ReadDomainsFromFile(domainsFile)
	}

	if len(args) == 0 {
		return nil, fmt.Errorf("no domains specified")
	}

	return args, nil
}

func runCheck(cmd *cobra.Command, args []string) error {
	domains, err := getDomains(cmd, args)
	if err != nil {
		return err
	}

	c := createChecker()

	if verbose {
		fmt.Printf("Checking %d domains with DNS server: %s\n", len(domains), getDisplayDNSServer())
	}

	results, errors := c.CheckDomains(domains)

	// Print errors if any
	if len(errors) > 0 {
		fmt.Fprintf(os.Stderr, "Errors encountered:\n")
		for _, err := range errors {
			fmt.Fprintf(os.Stderr, "  - %v\n", err)
		}
		fmt.Fprintf(os.Stderr, "\n")
	}

	return outputResults(results, errors)
}

func runSPF(cmd *cobra.Command, args []string) error {
	c := createChecker()

	var results []interface{}
	for _, domain := range args {
		result, err := c.GetSPFRecord(domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking SPF for %s: %v\n", domain, err)
			continue
		}
		results = append(results, result)
	}

	return outputGenericResults(results)
}

func runDKIM(cmd *cobra.Command, args []string) error {
	c := createChecker()

	var results []interface{}
	for _, domain := range args {
		result, err := c.GetDKIMRecord(domain, dkimSelector)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking DKIM for %s: %v\n", domain, err)
			continue
		}
		results = append(results, result)
	}

	return outputGenericResults(results)
}

func runDMARC(cmd *cobra.Command, args []string) error {
	c := createChecker()

	var results []interface{}
	for _, domain := range args {
		result, err := c.GetDMARCRecord(domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking DMARC for %s: %v\n", domain, err)
			continue
		}
		results = append(results, result)
	}

	return outputGenericResults(results)
}

func runDNSSEC(cmd *cobra.Command, args []string) error {
	c := createChecker()

	var results []interface{}
	for _, domain := range args {
		result, err := c.GetDNSSECRecord(domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking DNSSEC for %s: %v\n", domain, err)
			continue
		}
		results = append(results, result)
	}

	return outputGenericResults(results)
}

func runMTASTS(cmd *cobra.Command, args []string) error {
	c := createChecker()

	var results []interface{}
	for _, domain := range args {
		result, err := c.GetMTASTSRecord(domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking MTA-STS for %s: %v\n", domain, err)
			continue
		}
		results = append(results, result)
	}

	return outputGenericResults(results)
}

func runSummary(cmd *cobra.Command, args []string) error {
	domains, err := getDomains(cmd, args)
	if err != nil {
		return err
	}

	c := createChecker()
	results, errors := c.CheckDomains(domains)

	// Print errors if any
	if len(errors) > 0 {
		fmt.Fprintf(os.Stderr, "Errors encountered during checks:\n")
		for _, err := range errors {
			fmt.Fprintf(os.Stderr, "  - %v\n", err)
		}
		fmt.Fprintf(os.Stderr, "\n")
	}

	summary := checker.GetSummary(results)

	switch outputFormat {
	case "json":
		return outputJSON(summary)
	default:
		return outputSummaryTable(summary)
	}
}

func runValidate(cmd *cobra.Command, args []string) error {
	recordType := args[0]
	recordValue := args[1]

	var issues []string

	switch strings.ToLower(recordType) {
	case "spf":
		issues = checker.ValidateSPFRecord(recordValue)
	case "dkim":
		issues = checker.ValidateDKIMRecord(recordValue)
	case "dmarc":
		issues = checker.ValidateDMARCRecord(recordValue)
	case "mta-sts":
		issues = checker.ValidateMTASTSRecord(recordValue)
	default:
		return fmt.Errorf("unsupported record type: %s (supported: spf, dkim, dmarc, mta-sts)", recordType)
	}

	if len(issues) == 0 {
		fmt.Printf("✓ %s record is valid\n", strings.ToUpper(recordType))
	} else {
		fmt.Printf("✗ %s record has issues:\n", strings.ToUpper(recordType))
		for _, issue := range issues {
			fmt.Printf("  - %s\n", issue)
		}
	}

	return nil
}

func outputResults(results []*checker.DomainHealthResult, errors []error) error {
	switch outputFormat {
	case "json":
		return outputJSON(results)
	case "csv":
		return outputCSV(results)
	default:
		return outputTable(results)
	}
}

func outputGenericResults(results []interface{}) error {
	switch outputFormat {
	case "json":
		return outputJSON(results)
	default:
		return outputJSON(results) // Default to JSON for specific checks
	}
}

func outputJSON(data interface{}) error {
	encoder := json.NewEncoder(getOutputWriter())
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func outputTable(results []*checker.DomainHealthResult) error {
	writer := getOutputWriter()

	// Header
	fmt.Fprintf(writer, "%-20s %-10s %-10s %-10s %-10s %-10s\n",
		"Domain", "SPF", "DKIM", "DMARC", "MTA-STS", "DNSSEC")
	fmt.Fprintf(writer, "%s\n", strings.Repeat("-", 80))

	// Data rows
	for _, result := range results {
		spfStatus := getStatus(result.SPFRecord)
		dkimStatus := getStatus(result.DKIMRecord)
		dmarcStatus := getStatus(result.DMARCRecord)
		mtaStatus := getStatus(result.MTARecord)
		dnssecStatus := getStatus(result.DNSSEC)

		fmt.Fprintf(writer, "%-20s %-10s %-10s %-10s %-10s %-10s\n",
			truncateString(result.Name, 20),
			spfStatus,
			dkimStatus,
			dmarcStatus,
			mtaStatus,
			dnssecStatus)
	}

	return nil
}

func outputCSV(results []*checker.DomainHealthResult) error {
	writer := getOutputWriter()

	// Header
	fmt.Fprintf(writer, "Domain,SPF Record,SPF Advisory,DKIM Record,DKIM Advisory,DMARC Record,DMARC Advisory,MTA-STS Record,MTA-STS Advisory,DNSSEC,DNSSEC Advisory\n")

	// Data rows
	for _, result := range results {
		fmt.Fprintf(writer, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			csvEscape(result.Name),
			csvEscape(result.SPFRecord),
			csvEscape(result.SPFAdvisory),
			csvEscape(result.DKIMRecord),
			csvEscape(result.DKIMAdvisory),
			csvEscape(result.DMARCRecord),
			csvEscape(result.DMARCAdvisory),
			csvEscape(result.MTARecord),
			csvEscape(result.MTAAdvisory),
			csvEscape(result.DNSSEC),
			csvEscape(result.DNSSECAdvisory))
	}

	return nil
}

func outputSummaryTable(summary *checker.HealthSummary) error {
	writer := getOutputWriter()

	fmt.Fprintf(writer, "Domain Health Summary\n")
	fmt.Fprintf(writer, "====================\n\n")

	fmt.Fprintf(writer, "Total Domains: %d\n\n", summary.TotalDomains)

	fmt.Fprintf(writer, "SPF Configuration:\n")
	fmt.Fprintf(writer, "  Configured: %d (%.1f%%)\n", summary.SPFConfigured, summary.SPFPercentage)
	fmt.Fprintf(writer, "  Strict Policy: %d\n\n", summary.SPFStrict)

	fmt.Fprintf(writer, "DKIM Configuration:\n")
	fmt.Fprintf(writer, "  Configured: %d (%.1f%%)\n\n", summary.DKIMConfigured, summary.DKIMPercentage)

	fmt.Fprintf(writer, "DMARC Configuration:\n")
	fmt.Fprintf(writer, "  Configured: %d (%.1f%%)\n", summary.DMARCConfigured, summary.DMARCPercentage)
	fmt.Fprintf(writer, "  Reject Policy: %d\n\n", summary.DMARCReject)

	fmt.Fprintf(writer, "MTA-STS Configuration:\n")
	fmt.Fprintf(writer, "  Configured: %d (%.1f%%)\n\n", summary.MTASTSConfigured, summary.MTASTSPercentage)

	fmt.Fprintf(writer, "DNSSEC Configuration:\n")
	fmt.Fprintf(writer, "  Enabled: %d (%.1f%%)\n", summary.DNSSECEnabled, summary.DNSSECPercentage)

	return nil
}

func getOutputWriter() *os.File {
	if outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			return os.Stdout
		}
		return file
	}
	return os.Stdout
}

func getStatus(record string) string {
	if record == "" {
		return "✗"
	}
	return "✓"
}

func truncateString(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length-3] + "..."
}

func csvEscape(s string) string {
	if strings.Contains(s, ",") || strings.Contains(s, "\"") || strings.Contains(s, "\n") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

func getDisplayDNSServer() string {
	if dnsServer == "" {
		return "system default"
	}
	return dnsServer
}
