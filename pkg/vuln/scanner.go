// pkg/vuln/scanner.go
// Lightweight vulnerability matcher.
// Maps ServiceInfo (service name, product, version) to known CVEs / misconfigs.
// No network calls are required — this is a local signature database.
// Extend sig_db.go with new entries as needed.

package vuln

import (
	"fmt"
	"strings"

	"naabu-dev/pkg/banner"
)

// ─── Types ────────────────────────────────────────────────────────────────────

// Severity levels (mirrors CVSS qualitative scale).
type Severity int

const (
	Info     Severity = iota // informational / best-practice
	Low                      // CVSS 0.1–3.9
	Medium                   // CVSS 4.0–6.9
	High                     // CVSS 7.0–8.9
	Critical                 // CVSS 9.0–10.0
)

func (s Severity) String() string {
	return [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}[s]
}

// Finding is a single matched vulnerability / misconfiguration.
type Finding struct {
	CVE         string   // e.g. "CVE-2021-41773"
	Title       string   // short human title
	Description string   // detailed description
	Severity    Severity // severity level
	CVSS        float32  // CVSS score
	References  []string // URLs
	Service     string   // which service triggered this
	Port        int
	Host        string
}

// ─── Public API ───────────────────────────────────────────────────────────────

// Scan checks a ServiceInfo against the built-in signature database and
// returns all matched findings. Returns an empty slice (not nil) if clean.
func Scan(si *banner.ServiceInfo) []Finding {
	var findings []Finding

	svcLower := strings.ToLower(si.ServiceName)
	productLower := strings.ToLower(si.Product)
	versionStr := si.Version
	bannerLower := strings.ToLower(si.RawBanner)

	for _, sig := range sigDB {
		if matchSig(sig, svcLower, productLower, versionStr, bannerLower, si.Port) {
			findings = append(findings, Finding{
				CVE:         sig.CVE,
				Title:       sig.Title,
				Description: sig.Description,
				Severity:    sig.Severity,
				CVSS:        sig.CVSS,
				References:  sig.References,
				Service:     si.ServiceName,
				Port:        si.Port,
				Host:        si.Host,
			})
		}
	}

	// Always add exposure info for certain services
	findings = append(findings, exposureChecks(si)...)
	return findings
}

// ─── Signature Matching ───────────────────────────────────────────────────────

type sigEntry struct {
	CVE         string
	Title       string
	Description string
	Severity    Severity
	CVSS        float32
	References  []string
	// match criteria (all non-empty fields must match)
	MatchService string // substring in service name
	MatchProduct string // substring in product name
	MatchBanner  string // substring in raw banner
	Port         int    // 0 = any port
	MaxVersion   string // versions ≤ this are vulnerable (semver-lite)
}

func matchSig(sig sigEntry, svc, product, version, rawBanner string, port int) bool {
	if sig.Port != 0 && sig.Port != port {
		return false
	}
	if sig.MatchService != "" && !strings.Contains(svc, strings.ToLower(sig.MatchService)) {
		return false
	}
	if sig.MatchProduct != "" && !strings.Contains(product, strings.ToLower(sig.MatchProduct)) {
		return false
	}
	if sig.MatchBanner != "" && !strings.Contains(rawBanner, strings.ToLower(sig.MatchBanner)) {
		return false
	}
	if sig.MaxVersion != "" && version != "" {
		// Simple lexicographic compare — good enough for X.Y.Z strings
		if version > sig.MaxVersion {
			return false
		}
	}
	return true
}

// ─── Exposure Checks (service-level, not CVE-specific) ───────────────────────

func exposureChecks(si *banner.ServiceInfo) []Finding {
	var findings []Finding
	add := func(f Finding) { findings = append(findings, f) }

	svc := strings.ToLower(si.ServiceName)

	// Exposed admin interfaces
	switch {
	case strings.Contains(svc, "redis"):
		add(Finding{
			Title:       "Redis exposed without authentication",
			Description: "Redis running on a public/network interface with default config has no authentication. An attacker can read/write all data and execute arbitrary commands via EVAL.",
			Severity:    Critical,
			CVSS:        9.8,
			References:  []string{"https://redis.io/docs/management/security/"},
			Service:     si.ServiceName,
			Port:        si.Port,
			Host:        si.Host,
		})

	case strings.Contains(svc, "mongodb"):
		add(Finding{
			Title:       "MongoDB exposed without authentication",
			Description: "MongoDB listens on a network interface without authentication enabled. All data is publicly readable/writable.",
			Severity:    Critical,
			CVSS:        9.8,
			References:  []string{"https://docs.mongodb.com/manual/security/"},
			Service:     si.ServiceName,
			Port:        si.Port,
			Host:        si.Host,
		})

	case strings.Contains(svc, "elasticsearch"):
		add(Finding{
			Title:       "Elasticsearch exposed without authentication",
			Description: "Elasticsearch cluster is accessible without authentication. Sensitive index data may be exfiltrated.",
			Severity:    High,
			CVSS:        7.5,
			References:  []string{"https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html"},
			Service:     si.ServiceName,
			Port:        si.Port,
			Host:        si.Host,
		})

	case strings.Contains(svc, "vnc"):
		add(Finding{
			Title:       "VNC service exposed",
			Description: "VNC remote desktop is accessible over the network. If unauthenticated or using weak credentials, full desktop access is possible.",
			Severity:    High,
			CVSS:        7.5,
			References:  []string{"https://attack.mitre.org/techniques/T1021/005/"},
			Service:     si.ServiceName,
			Port:        si.Port,
			Host:        si.Host,
		})

	case strings.Contains(svc, "telnet"):
		add(Finding{
			Title:       "Telnet service (plaintext credentials)",
			Description: "Telnet transmits credentials and data in cleartext. It should be replaced with SSH.",
			Severity:    High,
			CVSS:        7.3,
			References:  []string{"https://cwe.mitre.org/data/definitions/319.html"},
			Service:     si.ServiceName,
			Port:        si.Port,
			Host:        si.Host,
		})

	case strings.Contains(svc, "ftp"):
		add(Finding{
			Title:       "FTP service (plaintext credentials)",
			Description: "FTP transmits credentials in cleartext and is susceptible to credential sniffing. Consider FTPS or SFTP.",
			Severity:    Medium,
			CVSS:        5.9,
			References:  []string{"https://cwe.mitre.org/data/definitions/319.html"},
			Service:     si.ServiceName,
			Port:        si.Port,
			Host:        si.Host,
		})

	case (si.Port == 2375) && strings.Contains(svc, "docker"):
		add(Finding{
			Title:       "Docker API exposed without TLS",
			Description: "Docker daemon API is exposed without TLS. An attacker can spawn privileged containers and escape to the host.",
			Severity:    Critical,
			CVSS:        9.8,
			References:  []string{"https://docs.docker.com/engine/security/protect-access/"},
			Service:     si.ServiceName,
			Port:        si.Port,
			Host:        si.Host,
		})
	}

	return findings
}

// ─── Signature Database ───────────────────────────────────────────────────────
// Each entry represents a specific known CVE tied to product/version/banner fingerprints.

var sigDB = []sigEntry{
	// ── SSH ──────────────────────────────────────────────────────────────────
	{
		CVE:          "CVE-2023-38408",
		Title:        "OpenSSH ssh-agent remote code execution",
		Description:  "A vulnerability in the PKCS#11 support of OpenSSH ssh-agent before 9.3p2 allows a remote attacker to execute code via a compromised agent-forwarding connection.",
		Severity:     Critical,
		CVSS:         9.8,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-38408"},
		MatchProduct: "openssh",
		MaxVersion:   "9.3p1",
	},
	{
		CVE:          "CVE-2016-0777",
		Title:        "OpenSSH roaming info-leak (≤ 7.1p1)",
		Description:  "The resync feature in OpenSSH ≤ 7.1p1 allows remote servers to obtain sensitive information from process memory.",
		Severity:     Medium,
		CVSS:         6.4,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2016-0777"},
		MatchProduct: "openssh",
		MaxVersion:   "7.1p1",
	},

	// ── Apache httpd ─────────────────────────────────────────────────────────
	{
		CVE:          "CVE-2021-41773",
		Title:        "Apache httpd 2.4.49 path traversal / RCE",
		Description:  "A flaw in path normalization in Apache HTTP Server 2.4.49 allows an attacker to map URLs outside the expected document root. If CGI scripts are enabled, remote code execution is possible.",
		Severity:     Critical,
		CVSS:         9.8,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
		MatchProduct: "apache",
		MaxVersion:   "2.4.49",
	},
	{
		CVE:          "CVE-2021-42013",
		Title:        "Apache httpd 2.4.49–2.4.50 path traversal / RCE",
		Description:  "Incomplete fix for CVE-2021-41773 in Apache 2.4.50 still allows path traversal and RCE via crafted request.",
		Severity:     Critical,
		CVSS:         9.8,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-42013"},
		MatchProduct: "apache",
		MaxVersion:   "2.4.50",
	},

	// ── nginx ────────────────────────────────────────────────────────────────
	{
		CVE:          "CVE-2021-23017",
		Title:        "nginx 1-byte heap overflow in resolver (< 1.20.1)",
		Description:  "A 1-byte memory overwrite in the nginx DNS resolver can lead to worker process crash or code execution.",
		Severity:     High,
		CVSS:         7.7,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-23017"},
		MatchProduct: "nginx",
		MaxVersion:   "1.20.0",
	},

	// ── OpenSSL / HTTPS ──────────────────────────────────────────────────────
	{
		CVE:         "CVE-2014-0160",
		Title:       "Heartbleed (OpenSSL memory disclosure)",
		Description: "The TLS heartbeat extension in OpenSSL 1.0.1 through 1.0.1f leaks up to 64 KB of server memory per request, potentially exposing private keys and session tokens.",
		Severity:    Critical,
		CVSS:        7.5,
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2014-0160", "https://heartbleed.com"},
		MatchBanner: "openssl/1.0.1",
	},

	// ── FTP ──────────────────────────────────────────────────────────────────
	{
		CVE:         "CVE-2011-2523",
		Title:       "vsftpd 2.3.4 backdoor",
		Description: "vsftpd 2.3.4 distributed via some mirrors contained a backdoor allowing unauthenticated command execution on port 6200.",
		Severity:    Critical,
		CVSS:        10.0,
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2011-2523"},
		MatchBanner: "vsftpd 2.3.4",
	},

	// ── SMTP ─────────────────────────────────────────────────────────────────
	{
		CVE:         "CVE-2010-4344",
		Title:       "Exim 4.69 remote code execution",
		Description: "A heap overflow in Exim 4.69 can be exploited by sending a long EHLO string, leading to remote code execution as root.",
		Severity:    Critical,
		CVSS:        9.3,
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2010-4344"},
		MatchBanner: "exim 4.69",
	},

	// ── Redis ────────────────────────────────────────────────────────────────
	{
		CVE:          "CVE-2022-0543",
		Title:        "Redis Lua sandbox escape (< 6.2.7 / < 7.0.1)",
		Description:  "A Lua sandbox escape vulnerability in Redis allowed execution of arbitrary code on the server via crafted EVAL commands.",
		Severity:     Critical,
		CVSS:         10.0,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-0543"},
		MatchService: "redis",
		MaxVersion:   "6.2.6",
	},

	// ── Docker ───────────────────────────────────────────────────────────────
	{
		CVE:          "CVE-2019-5736",
		Title:        "runc container escape",
		Description:  "runc < 1.0-rc6 allows a malicious container to overwrite the host runc binary, enabling host takeover.",
		Severity:     Critical,
		CVSS:         8.6,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-5736"},
		MatchService: "docker",
	},

	// ── Kubernetes ───────────────────────────────────────────────────────────
	{
		CVE:          "CVE-2018-1002105",
		Title:        "Kubernetes API server privilege escalation",
		Description:  "A flaw in the Kubernetes API server allowed an unauthenticated attacker to send arbitrary requests via an established websocket connection.",
		Severity:     Critical,
		CVSS:         9.8,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-1002105"},
		MatchService: "k8s",
		Port:         6443,
	},
}

// ─── Summary Reporter ────────────────────────────────────────────────────────

// PrintSummary prints a coloured vulnerability summary table to stdout.
func PrintSummary(all []Finding, noColor bool) {
	if len(all) == 0 {
		if !noColor {
			fmt.Printf("\n\033[32m[✓] No known vulnerabilities matched.\033[0m\n")
		} else {
			fmt.Println("\n[✓] No known vulnerabilities matched.")
		}
		return
	}

	fmt.Printf("\n%s╔══════════════════════════════════════════════════════════════╗%s\n",
		colorFor(noColor, "\033[1;31m"), reset)
	fmt.Printf("%s║              VULNERABILITY FINDINGS SUMMARY                 ║%s\n",
		colorFor(noColor, "\033[1;31m"), reset)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════════╝%s\n",
		colorFor(noColor, "\033[1;31m"), reset)

	counts := map[Severity]int{}
	for _, f := range all {
		counts[f.Severity]++
		printFinding(f, noColor)
	}

	fmt.Printf("\n%sTotals:%s  CRITICAL=%d  HIGH=%d  MEDIUM=%d  LOW=%d  INFO=%d\n",
		bold, reset,
		counts[Critical], counts[High], counts[Medium], counts[Low], counts[Info],
	)
}

func printFinding(f Finding, noColor bool) {
	sev := f.Severity.String()
	sevColor := map[Severity]string{
		Critical: "\033[1;35m",
		High:     "\033[1;31m",
		Medium:   "\033[1;33m",
		Low:      "\033[1;32m",
		Info:     "\033[1;36m",
	}[f.Severity]

	fmt.Printf("\n%s[%s]%s %s%s%s\n",
		colorFor(noColor, sevColor), sev, reset,
		colorFor(noColor, bold), f.Title, reset,
	)
	fmt.Printf("  Host/Port : %s:%d\n", f.Host, f.Port)
	if f.CVE != "" {
		fmt.Printf("  CVE       : %s  (CVSS %.1f)\n", f.CVE, f.CVSS)
	}
	// wrap description at 70 chars
	words := strings.Fields(f.Description)
	line := "  Desc      : "
	for _, w := range words {
		if len(line)+len(w)+1 > 80 {
			fmt.Println(line)
			line = "              " + w
		} else {
			if line != "  Desc      : " {
				line += " "
			}
			line += w
		}
	}
	fmt.Println(line)
	if len(f.References) > 0 {
		fmt.Printf("  Ref       : %s\n", f.References[0])
	}
}

func colorFor(noColor bool, code string) string {
	if noColor {
		return ""
	}
	return code
}
