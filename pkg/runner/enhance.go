// pkg/runner/enhance.go
// Drop-in additions to the Naabu runner package.
// Provides EnhancedOnResult — a replacement / wrapper for the default
// OnResult callback that:
//   1. Grabs a banner per discovered port (pkg/banner)
//   2. Renders a rich terminal display (pkg/banner/display)
//   3. Detects services and matches vulnerabilities (pkg/vuln)
//   4. Aggregates all findings for a final summary

package runner

import (
	"fmt"
	"sync"
	"time"

	"github.com/MohammadRezaHosseinian/Naabu/pkg/banner"
	"github.com/MohammadRezaHosseinian/Naabu/pkg/vuln"
	"github.com/projectdiscovery/gologger"
	naabuResult "github.com/projectdiscovery/naabu/v2/pkg/result"
)

// ─── Global accumulator (thread-safe) ────────────────────────────────────────

var (
	allFindings   []vuln.Finding
	findingsMutex sync.Mutex
)

// AddFindings records findings into the global accumulator.
func AddFindings(f []vuln.Finding) {
	findingsMutex.Lock()
	defer findingsMutex.Unlock()
	allFindings = append(allFindings, f...)
}

// AllFindings returns a copy of all accumulated findings.
func AllFindings() []vuln.Finding {
	findingsMutex.Lock()
	defer findingsMutex.Unlock()
	out := make([]vuln.Finding, len(allFindings))
	copy(out, allFindings)
	return out
}

// ─── Enhanced OnResult ────────────────────────────────────────────────────────

// EnhancedOnResult returns a callback compatible with runner.Options.OnResult.
// It wraps the original callback (pass nil if you don't have one) and adds
// banner grabbing + vulnerability scanning.
//
// Parameters:
//
//	original    – existing callback to chain (may be nil)
//	noColor     – disable ANSI color output
//	grabTimeout – per-port banner grab timeout
func EnhancedOnResult(
	original func(*naabuResult.HostResult),
	noColor bool,
	grabTimeout time.Duration,
) func(*naabuResult.HostResult) {

	if grabTimeout == 0 {
		grabTimeout = 5 * time.Second
	}

	return func(hr *naabuResult.HostResult) {
		// Chain original callback first (e.g. JSON output, file writer).
		if original != nil {
			original(hr)
		}

		// Process each open port concurrently.
		var wg sync.WaitGroup
		for _, p := range hr.Ports {
			wg.Add(1)
			go func(portNum int, proto string, isTLS bool) {
				defer wg.Done()

				// 1. Banner grab
				si := banner.Grab(hr.Host, hr.IP, portNum, proto, isTLS, grabTimeout)

				// 2. Render banner
				banner.Print(si, noColor)

				// 3. Vuln scan
				findings := vuln.Scan(si)
				if len(findings) > 0 {
					AddFindings(findings)
					for _, f := range findings {
						if noColor {
							gologger.Warning().Msgf("[VULN] %s:%d  %s  %s  (CVSS %.1f)",
								f.Host, f.Port, f.Severity, f.Title, f.CVSS)
						} else {
							gologger.Warning().Msgf("\033[1;31m[VULN]\033[0m %s:%d  \033[1;35m%s\033[0m  %s  (CVSS %.1f)",
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

// ScanMap holds aggregated results indexed by host.
type ScanMap struct {
	mu      sync.Mutex
	entries map[string]*HostScanResult
}

// HostScanResult stores everything we found for one host.
type HostScanResult struct {
	Host     string
	IP       string
	Services []*banner.ServiceInfo
	Findings []vuln.Finding
}

// NewScanMap creates an empty ScanMap.
func NewScanMap() *ScanMap {
	return &ScanMap{entries: map[string]*HostScanResult{}}
}

// Add records a ServiceInfo (and its findings) for a host.
func (m *ScanMap) Add(si *banner.ServiceInfo, findings []vuln.Finding) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := si.Host
	if m.entries[key] == nil {
		m.entries[key] = &HostScanResult{Host: si.Host, IP: si.IP}
	}
	m.entries[key].Services = append(m.entries[key].Services, si)
	m.entries[key].Findings = append(m.entries[key].Findings, findings...)
}

// All returns all collected HostScanResults.
func (m *ScanMap) All() []*HostScanResult {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]*HostScanResult, 0, len(m.entries))
	for _, v := range m.entries {
		out = append(out, v)
	}
	return out
}

// PrintMap renders the full scan map as a structured summary table.
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
			fmt.Printf("  %-6d %-8s %-20s %s%s\n",
				svc.Port,
				col("\033[36m", svc.Protocol),
				col("\033[33m", svc.ServiceName+" "+svc.Version),
				col("\033[90m", svc.Product),
				vulnStr,
			)
		}
	}
}
