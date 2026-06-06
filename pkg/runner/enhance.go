// pkg/runner/enhance.go
// Extends the existing runner package with:
//   - EnhancedOnResult  — wraps OnResult with banner grabbing + vuln scanning
//   - ScanMap           — aggregates all host/port/service/vuln results
//   - AllFindings()     — returns accumulated vulnerability findings
//
// This file belongs to package runner (same package as the upstream runner).
// Place it at:  pkg/runner/enhance.go

package runner

import (
	"fmt"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	naabuResult "naabu-dev/pkg/result"

	"naabu-dev/pkg/banner"

	// New sub-packages added by this fork
	"naabu-dev/pkg/vuln"
)

// ─── Global accumulator (thread-safe) ────────────────────────────────────────

var (
	allFindings   []vuln.Finding
	findingsMutex sync.Mutex
)

// AddFindings appends findings to the global accumulator.
func AddFindings(f []vuln.Finding) {
	findingsMutex.Lock()
	defer findingsMutex.Unlock()
	allFindings = append(allFindings, f...)
}

// AllFindings returns a snapshot of all accumulated findings.
func AllFindings() []vuln.Finding {
	findingsMutex.Lock()
	defer findingsMutex.Unlock()
	out := make([]vuln.Finding, len(allFindings))
	copy(out, allFindings)
	return out
}

// ─── Enhanced OnResult callback ───────────────────────────────────────────────

// EnhancedOnResult wraps any existing OnResult callback and additionally:
//  1. Grabs a protocol-aware banner for every discovered open port
//  2. Prints the banner as a rich coloured terminal block
//  3. Matches the banner against the CVE / exposure vulnerability database
//  4. Logs inline warnings for any findings
//
// Parameters:
//
//	original    – caller's existing OnResult (may be nil)
//	noColor     – when true, suppress ANSI colour codes
//	grabTimeout – max time to spend per banner grab
func EnhancedOnResult(
	original func(*naabuResult.HostResult),
	noColor bool,
	grabTimeout time.Duration,
) func(*naabuResult.HostResult) {

	if grabTimeout <= 0 {
		grabTimeout = 5 * time.Second
	}

	return func(hr *naabuResult.HostResult) {
		// Always call the upstream callback first (JSON output, file writer, …).
		if original != nil {
			original(hr)
		}

		// Grab banners and scan vulns concurrently — one goroutine per port.
		var wg sync.WaitGroup
		for _, p := range hr.Ports {
			wg.Add(1)
			go func(portNum int, proto string, isTLS bool) {
				defer wg.Done()

				// 1. Banner grab
				si := banner.Grab(hr.Host, hr.IP, portNum, proto, isTLS, grabTimeout)

				// 2. Render banner to terminal
				banner.Print(si, noColor)

				// 3. Vulnerability match
				findings := vuln.Scan(si)
				if len(findings) > 0 {
					AddFindings(findings)
					for _, f := range findings {
						if noColor {
							gologger.Warning().Msgf(
								"[VULN] %s:%d  %s  %s  (CVSS %.1f)",
								f.Host, f.Port, f.Severity, f.Title, f.CVSS)
						} else {
							gologger.Warning().Msgf(
								"\033[1;31m[VULN]\033[0m %s:%d  \033[1;35m%s\033[0m  %s  (CVSS %.1f)",
								f.Host, f.Port, f.Severity, f.Title, f.CVSS)
						}
					}
				}
			}(p.Port, p.Protocol.String(), p.TLS)
		}
		wg.Wait()
	}
}

// ─── Scan Map ─────────────────────────────────────────────────────────────────

// ScanMap accumulates everything discovered across all hosts.
type ScanMap struct {
	mu      sync.Mutex
	entries map[string]*HostScanResult
}

// HostScanResult holds all services and vulnerability findings for one host.
type HostScanResult struct {
	Host     string
	IP       string
	Services []*banner.ServiceInfo
	Findings []vuln.Finding
}

// NewScanMap constructs an empty ScanMap.
func NewScanMap() *ScanMap {
	return &ScanMap{entries: make(map[string]*HostScanResult)}
}

// Add stores a ServiceInfo (and associated findings) for a host.
func (m *ScanMap) Add(si *banner.ServiceInfo, findings []vuln.Finding) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.entries[si.Host] == nil {
		m.entries[si.Host] = &HostScanResult{Host: si.Host, IP: si.IP}
	}
	m.entries[si.Host].Services = append(m.entries[si.Host].Services, si)
	m.entries[si.Host].Findings = append(m.entries[si.Host].Findings, findings...)
}

// All returns every HostScanResult collected so far.
func (m *ScanMap) All() []*HostScanResult {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]*HostScanResult, 0, len(m.entries))
	for _, v := range m.entries {
		out = append(out, v)
	}
	return out
}

// PrintMap prints the full scan map table: host → ports → services → vuln count.
func (m *ScanMap) PrintMap(noColor bool) {
	results := m.All()
	if len(results) == 0 {
		return
	}

	col := func(code, s string) string {
		if noColor {
			return s
		}
		return code + s + "\033[0m"
	}

	fmt.Println()
	fmt.Println(col("\033[1;36m", "╔══════════════════════════════════════════════════════════════╗"))
	fmt.Println(col("\033[1;36m", "║                    FULL SCAN MAP                            ║"))
	fmt.Println(col("\033[1;36m", "╚══════════════════════════════════════════════════════════════╝"))

	for _, r := range results {
		fmt.Printf("\n%s  (IP: %s)\n", col("\033[1;37m", r.Host), r.IP)

		for _, svc := range r.Services {
			vulnCount := 0
			for _, f := range r.Findings {
				if f.Port == svc.Port {
					vulnCount++
				}
			}
			vulnStr := ""
			if vulnCount > 0 {
				vulnStr = col("\033[1;31m", fmt.Sprintf("  ⚠ %d vuln(s)", vulnCount))
			}
			svcLabel := svc.ServiceName
			if svc.Version != "" {
				svcLabel += " " + svc.Version
			}
			fmt.Printf("  %-6d %-8s %-22s %s%s\n",
				svc.Port,
				col("\033[36m", svc.Protocol),
				col("\033[33m", svcLabel),
				col("\033[90m", svc.Product),
				vulnStr,
			)
		}
	}
}
