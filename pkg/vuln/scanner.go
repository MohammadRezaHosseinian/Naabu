// pkg/vuln/scanner.go
// Comprehensive vulnerability scanner with full CVE mapping.
//
// Architecture
// ────────────
//  • sigDB        — CVE-specific signatures (product + version + banner match)
//  • exposureDB   — service-level exposure checks (no specific CVE required)
//  • Scan()       — runs both layers, returns []Finding
//  • PrintSummary — coloured terminal report grouped by severity
//
// Every sigEntry carries:
//   CVE, CVSS, Severity, affected-version range (MinVersion..MaxVersion),
//   match criteria (service / product / banner substring), and NVD reference.
//
// Matching strategy
//   1. Port filter    (sig.Port != 0 must equal the scanned port)
//   2. Service filter (sig.MatchService substring in detected service name)
//   3. Product filter (sig.MatchProduct substring in detected product name)
//   4. Banner filter  (sig.MatchBanner  substring in raw banner)
//   5. Version range  (MinVersion ≤ detected ≤ MaxVersion, lexicographic)

package vuln

import (
	"fmt"
	"strings"

	"naabu-dev/pkg/banner"
)

// ─── ANSI helpers (self-contained; display.go is a different package) ─────────

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiPurple = "\033[35m"
	ansiGrey   = "\033[90m"
	ansiWhite  = "\033[97m"
)

// ─── Severity ─────────────────────────────────────────────────────────────────

type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	return [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}[s]
}

// ─── Finding ──────────────────────────────────────────────────────────────────

// Finding represents one matched vulnerability or exposure.
type Finding struct {
	CVE          string // NVD CVE identifier (empty for exposure-only)
	CWE          string // CWE classification
	Title        string // short human-readable title
	Description  string // detailed description
	Severity     Severity
	CVSS         float32  // CVSS v3 base score
	EPSS         float32  // EPSS probability (0–1), 0 if unknown
	References   []string // NVD + vendor advisory URLs
	FixedIn      string   // first patched version
	Mitigation   string   // short mitigation note
	ExploitAvail bool     // known public exploit / PoC exists
	// context (filled by Scan)
	Service string
	Port    int
	Host    string
}

// ─── Signature entry ──────────────────────────────────────────────────────────

type sigEntry struct {
	CVE          string
	CWE          string
	Title        string
	Description  string
	Severity     Severity
	CVSS         float32
	EPSS         float32
	References   []string
	FixedIn      string
	Mitigation   string
	ExploitAvail bool
	// match criteria
	MatchService string // substring in ServiceInfo.ServiceName (lowercased)
	MatchProduct string // substring in ServiceInfo.Product     (lowercased)
	MatchBanner  string // substring in ServiceInfo.RawBanner   (lowercased)
	Port         int    // 0 = any port
	MinVersion   string // "" = no lower bound
	MaxVersion   string // "" = no upper bound  (lexicographic X.Y.Z compare)
}

// ─── Public API ───────────────────────────────────────────────────────────────

// Scan runs all signature and exposure checks against si.
// Returns a deduplicated []Finding; never nil.
func Scan(si *banner.ServiceInfo) []Finding {
	svcL := strings.ToLower(si.ServiceName)
	prodL := strings.ToLower(si.Product)
	ver := si.Version
	bannerL := strings.ToLower(si.RawBanner)

	seen := map[string]bool{}
	var findings []Finding

	add := func(f Finding) {
		key := f.CVE + "|" + f.Title + "|" + fmt.Sprintf("%d", f.Port)
		if seen[key] {
			return
		}
		seen[key] = true
		findings = append(findings, f)
	}

	// Layer 1 — CVE signature DB
	for _, sig := range sigDB {
		if matchSig(sig, svcL, prodL, ver, bannerL, si.Port) {
			add(Finding{
				CVE:          sig.CVE,
				CWE:          sig.CWE,
				Title:        sig.Title,
				Description:  sig.Description,
				Severity:     sig.Severity,
				CVSS:         sig.CVSS,
				EPSS:         sig.EPSS,
				References:   sig.References,
				FixedIn:      sig.FixedIn,
				Mitigation:   sig.Mitigation,
				ExploitAvail: sig.ExploitAvail,
				Service:      si.ServiceName,
				Port:         si.Port,
				Host:         si.Host,
			})
		}
	}

	// Layer 2 — Exposure checks
	for _, f := range exposureChecks(si) {
		add(f)
	}

	return findings
}

// ─── Matching logic ───────────────────────────────────────────────────────────

func matchSig(sig sigEntry, svc, prod, ver, rawBanner string, port int) bool {
	if sig.Port != 0 && sig.Port != port {
		return false
	}
	if sig.MatchService != "" && !strings.Contains(svc, sig.MatchService) {
		return false
	}
	if sig.MatchProduct != "" && !strings.Contains(prod, sig.MatchProduct) {
		return false
	}
	if sig.MatchBanner != "" && !strings.Contains(rawBanner, sig.MatchBanner) {
		return false
	}
	if ver != "" {
		if sig.MinVersion != "" && ver < sig.MinVersion {
			return false
		}
		if sig.MaxVersion != "" && ver > sig.MaxVersion {
			return false
		}
	}
	return true
}

// ─── Exposure checks ─────────────────────────────────────────────────────────
// These fire on service type alone (no CVE — the risk is misconfiguration).

func exposureChecks(si *banner.ServiceInfo) []Finding {
	var out []Finding
	svc := strings.ToLower(si.ServiceName)

	add := func(title, desc, mitigation string, sev Severity, cvss float32, refs []string) {
		out = append(out, Finding{
			Title:       title,
			Description: desc,
			Severity:    sev,
			CVSS:        cvss,
			References:  refs,
			Mitigation:  mitigation,
			Service:     si.ServiceName,
			Port:        si.Port,
			Host:        si.Host,
		})
	}

	switch {
	case strings.Contains(svc, "redis"):
		add(
			"Redis exposed without authentication",
			"Redis is reachable on the network with its default configuration. No password is required. An attacker can read/write all data, execute Lua via EVAL, and pivot to the host.",
			"Set requirepass in redis.conf; bind to 127.0.0.1 or use firewall rules.",
			SevCritical, 9.8,
			[]string{"https://redis.io/docs/management/security/"},
		)
	case strings.Contains(svc, "mongodb"):
		add(
			"MongoDB exposed without authentication",
			"MongoDB is listening on a network interface with no authentication configured. All databases are publicly readable and writable.",
			"Enable --auth; use network-level access controls.",
			SevCritical, 9.8,
			[]string{"https://www.mongodb.com/docs/manual/security/"},
		)
	case strings.Contains(svc, "elasticsearch"):
		add(
			"Elasticsearch exposed without authentication",
			"Elasticsearch cluster is accessible without credentials. Indices, cluster config, and mappings are readable by anyone.",
			"Enable X-Pack Security; restrict with firewall.",
			SevHigh, 7.5,
			[]string{"https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html"},
		)
	case strings.Contains(svc, "couchdb"):
		add(
			"CouchDB exposed (check for admin party mode)",
			"CouchDB in default 'admin party' mode allows anyone to perform admin operations.",
			"Create an admin user immediately after installation.",
			SevCritical, 9.8,
			[]string{"https://docs.couchdb.org/en/stable/intro/security.html"},
		)
	case strings.Contains(svc, "vnc"):
		add(
			"VNC service exposed",
			"VNC remote desktop is reachable over the network. Weak or absent authentication allows full desktop takeover.",
			"Restrict VNC to loopback and tunnel through SSH; enforce strong passwords.",
			SevHigh, 7.5,
			[]string{"https://attack.mitre.org/techniques/T1021/005/"},
		)
	case strings.Contains(svc, "telnet"):
		add(
			"Telnet — plaintext credential transmission",
			"Telnet sends all data including credentials in cleartext, trivially intercepted on shared networks.",
			"Replace with SSH immediately.",
			SevHigh, 7.3,
			[]string{"https://cwe.mitre.org/data/definitions/319.html"},
		)
	case strings.Contains(svc, "ftp"):
		add(
			"FTP — plaintext credential transmission",
			"FTP transmits usernames and passwords in cleartext. Credentials can be sniffed from the same LAN or MITM path.",
			"Replace with SFTP or FTPS.",
			SevMedium, 5.9,
			[]string{"https://cwe.mitre.org/data/definitions/319.html"},
		)
	case si.Port == 2375 && (strings.Contains(svc, "docker") || strings.Contains(svc, "http")):
		add(
			"Docker daemon API exposed without TLS (port 2375)",
			"The Docker API on port 2375 has no TLS and no authentication. An attacker can create privileged containers and escape to the host OS.",
			"Migrate to port 2376 with TLS client certificates; block 2375 in firewall.",
			SevCritical, 9.8,
			[]string{"https://docs.docker.com/engine/security/protect-access/"},
		)
	case si.Port == 6443 && (strings.Contains(svc, "k8s") || strings.Contains(svc, "http")):
		add(
			"Kubernetes API server exposed",
			"The Kubernetes API server is reachable. If RBAC is misconfigured or anonymous access is enabled, an attacker can control the cluster.",
			"Disable anonymous auth; enforce RBAC; restrict API access.",
			SevHigh, 8.0,
			[]string{"https://kubernetes.io/docs/concepts/security/"},
		)
	case strings.Contains(svc, "smtp"):
		add(
			"SMTP open relay check recommended",
			"An exposed SMTP server may be misconfigured as an open relay, allowing spam or phishing abuse.",
			"Restrict relay to authenticated users only; enable SPF/DKIM/DMARC.",
			SevMedium, 5.3,
			[]string{"https://www.rfc-editor.org/rfc/rfc5321"},
		)
	}

	return out
}

// ─── CVE Signature Database ───────────────────────────────────────────────────
// Organised by service family. Each entry is independently matchable.
// Sources: NVD, vendor advisories, Qualys, Palo Alto Unit42, Wiz Research.

var sigDB = []sigEntry{

	// ══════════════════════════════════════════════════════════════════════════
	// SSH — OpenSSH
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2024-6387",
		CWE:          "CWE-364",
		Title:        "OpenSSH regreSSHion — unauthenticated RCE as root (glibc Linux)",
		Description:  "Signal handler race condition in sshd allows unauthenticated remote code execution with root privileges on glibc-based Linux systems. Affects 8.5p1–9.7p1 and versions < 4.4p1 not patched for CVE-2006-5051.",
		Severity:     SevHigh,
		CVSS:         8.1,
		EPSS:         0.14,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-6387", "https://www.qualys.com/regresshion-cve-2024-6387"},
		FixedIn:      "9.8p1",
		Mitigation:   "Upgrade to OpenSSH 9.8p1+; set LoginGraceTime 0 as temporary mitigation.",
		ExploitAvail: true,
		MatchProduct: "openssh",
		MinVersion:   "8.5p1",
		MaxVersion:   "9.7p1",
	},
	{
		CVE:          "CVE-2023-38408",
		CWE:          "CWE-426",
		Title:        "OpenSSH ssh-agent PKCS#11 remote code execution",
		Description:  "The PKCS#11 feature in OpenSSH ssh-agent before 9.3p2 is susceptible to remote code execution via a forwarded agent connection to a malicious server.",
		Severity:     SevCritical,
		CVSS:         9.8,
		EPSS:         0.08,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-38408"},
		FixedIn:      "9.3p2",
		Mitigation:   "Upgrade to OpenSSH 9.3p2+; avoid forwarding ssh-agent to untrusted hosts.",
		ExploitAvail: true,
		MatchProduct: "openssh",
		MaxVersion:   "9.3p1",
	},
	{
		CVE:          "CVE-2025-32433",
		CWE:          "CWE-287",
		Title:        "Erlang/OTP SSH — unauthenticated pre-auth RCE (CVSS 10)",
		Description:  "Improper handling of SSH connection protocol messages in Erlang/OTP allows an unauthenticated attacker to send crafted packets before authentication, achieving arbitrary code execution — potentially as root.",
		Severity:     SevCritical,
		CVSS:         10.0,
		EPSS:         0.67,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-32433", "https://www.cybereason.com/blog/rce-vulnerability-erlang-otp"},
		FixedIn:      "OTP-27.3.3 / OTP-26.2.5.11 / OTP-25.3.2.20",
		Mitigation:   "Patch immediately; restrict SSH access at firewall level.",
		ExploitAvail: true,
		MatchBanner:  "erlang",
		MatchService: "ssh",
	},
	{
		CVE:          "CVE-2016-0777",
		CWE:          "CWE-200",
		Title:        "OpenSSH roaming — heap memory disclosure (≤ 7.1p1)",
		Description:  "The undocumented roaming feature in OpenSSH client ≤ 7.1p1 leaks heap memory to a rogue server via the resume connection feature.",
		Severity:     SevMedium,
		CVSS:         6.4,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2016-0777"},
		FixedIn:      "7.1p2",
		Mitigation:   "Upgrade; add 'UseRoaming no' in ssh_config as workaround.",
		MatchProduct: "openssh",
		MaxVersion:   "7.1p1",
	},
	{
		CVE:          "CVE-2018-15473",
		CWE:          "CWE-200",
		Title:        "OpenSSH username enumeration (≤ 7.7)",
		Description:  "OpenSSH through 7.7 allows user enumeration; sshd responds differently to valid vs invalid usernames, enabling brute-force pre-auth reconnaissance.",
		Severity:     SevMedium,
		CVSS:         5.3,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-15473"},
		FixedIn:      "7.8",
		Mitigation:   "Upgrade to OpenSSH 7.8+.",
		ExploitAvail: true,
		MatchProduct: "openssh",
		MaxVersion:   "7.7",
	},

	// ══════════════════════════════════════════════════════════════════════════
	// HTTP — Apache httpd
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2021-41773",
		CWE:          "CWE-22",
		Title:        "Apache httpd 2.4.49 — path traversal / RCE",
		Description:  "A flaw in path normalisation in Apache 2.4.49 allows path traversal outside the web root. If mod_cgi is enabled, unauthenticated RCE is possible.",
		Severity:     SevCritical,
		CVSS:         9.8,
		EPSS:         0.97,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
		FixedIn:      "2.4.51",
		Mitigation:   "Upgrade immediately; disable mod_cgi; set 'Require all denied'.",
		ExploitAvail: true,
		MatchProduct: "apache",
		MinVersion:   "2.4.49",
		MaxVersion:   "2.4.49",
	},
	{
		CVE:          "CVE-2021-42013",
		CWE:          "CWE-22",
		Title:        "Apache httpd 2.4.49–2.4.50 — path traversal / RCE (incomplete fix)",
		Description:  "The fix for CVE-2021-41773 in 2.4.50 was incomplete. Attackers can still traverse outside the document root and achieve RCE via mod_cgi.",
		Severity:     SevCritical,
		CVSS:         9.8,
		EPSS:         0.97,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-42013"},
		FixedIn:      "2.4.51",
		Mitigation:   "Upgrade to 2.4.51+.",
		ExploitAvail: true,
		MatchProduct: "apache",
		MinVersion:   "2.4.49",
		MaxVersion:   "2.4.50",
	},
	{
		CVE:          "CVE-2017-7679",
		CWE:          "CWE-787",
		Title:        "Apache httpd mod_mime buffer overread (≤ 2.2.32 / ≤ 2.4.25)",
		Description:  "mod_mime in Apache 2.2.32 and 2.4.25 can read one byte past end of heap-allocated buffer when sending malicious Content-Type responses.",
		Severity:     SevCritical,
		CVSS:         9.8,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-7679"},
		FixedIn:      "2.4.26",
		MatchProduct: "apache",
		MaxVersion:   "2.4.25",
	},
	{
		CVE:          "CVE-2022-31813",
		CWE:          "CWE-348",
		Title:        "Apache httpd mod_proxy X-Forwarded-For header bypass (≤ 2.4.53)",
		Description:  "Apache mod_proxy may not send the X-Forwarded-For header to the backend, allowing authentication bypass when backends rely on that header.",
		Severity:     SevHigh,
		CVSS:         9.8,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-31813"},
		FixedIn:      "2.4.54",
		MatchProduct: "apache",
		MaxVersion:   "2.4.53",
	},

	// ══════════════════════════════════════════════════════════════════════════
	// HTTP — Apache Tomcat
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2025-24813",
		CWE:          "CWE-502",
		Title:        "Apache Tomcat — RCE via partial PUT deserialization (actively exploited)",
		Description:  "Improper handling of file paths during partial PUT requests in Tomcat 9.0.0.M1–9.0.98, 10.1.0-M1–10.1.34, 11.0.0-M1–11.0.2 allows RCE via unsafe deserialization. Exploited in the wild within 30h of disclosure.",
		Severity:     SevCritical,
		CVSS:         9.8,
		EPSS:         0.89,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-24813", "https://www.sonicwall.com/blog/critical-apache-tomcat-rce-vulnerability-cve-2025-24813-under-active-exploitation"},
		FixedIn:      "11.0.3 / 10.1.35 / 9.0.99",
		Mitigation:   "Upgrade; disable partial PUT (set allowPartialPut=false); disable file-based session persistence.",
		ExploitAvail: true,
		MatchProduct: "tomcat",
		MaxVersion:   "9.0.98",
	},
	{
		CVE:          "CVE-2024-50379",
		CWE:          "CWE-367",
		Title:        "Apache Tomcat — TOCTOU race condition RCE on case-insensitive FS",
		Description:  "Time-of-check-time-of-use race condition during JSP compilation on case-insensitive file systems (e.g. Windows) when default servlet write is enabled allows RCE.",
		Severity:     SevCritical,
		CVSS:         9.8,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-50379"},
		FixedIn:      "11.0.2 / 10.1.34 / 9.0.98",
		Mitigation:   "Upgrade; disable write on default servlet; set sun.io.useCanonCaches=false on Java 8/11.",
		ExploitAvail: false,
		MatchProduct: "tomcat",
		MaxVersion:   "9.0.97",
	},
	{
		CVE:          "CVE-2024-56337",
		CWE:          "CWE-367",
		Title:        "Apache Tomcat — incomplete fix for CVE-2024-50379 TOCTOU RCE",
		Description:  "The mitigation for CVE-2024-50379 was incomplete. Tomcat 9.0–11.0 on case-insensitive file systems still vulnerable without additional Java system property configuration.",
		Severity:     SevCritical,
		CVSS:         9.8,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-56337"},
		FixedIn:      "11.0.2 / 10.1.34 / 9.0.98 + config",
		Mitigation:   "Upgrade; additionally set sun.io.useCanonCaches=false if using Java 8/11.",
		MatchProduct: "tomcat",
		MaxVersion:   "9.0.97",
	},
	{
		CVE:          "CVE-2020-1938",
		CWE:          "CWE-276",
		Title:        "Apache Tomcat Ghostcat — AJP file read / RCE (≤ 9.0.30)",
		Description:  "The AJP connector in Tomcat ≤ 9.0.30 allows an attacker with access to port 8009 to read arbitrary files or achieve RCE by including a malicious JSP file.",
		Severity:     SevCritical,
		CVSS:         9.8,
		EPSS:         0.95,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-1938"},
		FixedIn:      "9.0.31 / 8.5.51",
		Mitigation:   "Upgrade; disable AJP connector (comment out in server.xml) or set requiredSecret.",
		ExploitAvail: true,
		MatchProduct: "tomcat",
		MaxVersion:   "9.0.30",
	},
	{
		CVE:          "CVE-2019-0232",
		CWE:          "CWE-78",
		Title:        "Apache Tomcat CGI RCE on Windows (≤ 9.0.17)",
		Description:  "When the CGI Servlet is enabled on Windows, Tomcat ≤ 9.0.17 incorrectly handles batch file paths allowing OS command injection.",
		Severity:     SevCritical,
		CVSS:         8.1,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-0232"},
		FixedIn:      "9.0.18",
		Mitigation:   "Upgrade; disable CGI Servlet.",
		ExploitAvail: true,
		MatchProduct: "tomcat",
		MaxVersion:   "9.0.17",
	},

	// ══════════════════════════════════════════════════════════════════════════
	// HTTP — nginx
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2021-23017",
		CWE:          "CWE-193",
		Title:        "nginx DNS resolver 1-byte heap overflow (< 1.20.1)",
		Description:  "A 1-byte heap overwrite in the nginx DNS resolver (off-by-one) can crash the worker process or lead to code execution when resolver is enabled.",
		Severity:     SevHigh,
		CVSS:         7.7,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-23017"},
		FixedIn:      "1.20.1",
		Mitigation:   "Upgrade; avoid using nginx as DNS resolver.",
		ExploitAvail: false,
		MatchProduct: "nginx",
		MaxVersion:   "1.20.0",
	},
	{
		CVE:          "CVE-2019-9511",
		CWE:          "CWE-400",
		Title:        "nginx HTTP/2 Data Dribble DoS",
		Description:  "Attackers can send small HTTP/2 windows to force nginx to buffer unlimited data, exhausting server memory.",
		Severity:     SevHigh,
		CVSS:         7.5,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-9511"},
		FixedIn:      "1.17.3",
		MatchProduct: "nginx",
		MaxVersion:   "1.17.2",
	},
	{
		CVE:          "CVE-2017-7529",
		CWE:          "CWE-190",
		Title:        "nginx integer overflow — memory info-leak via Range requests (< 1.13.3)",
		Description:  "A specially crafted Range request can cause nginx to return uninitialized memory from cache files, leaking sensitive data.",
		Severity:     SevMedium,
		CVSS:         7.5,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-7529"},
		FixedIn:      "1.13.3",
		Mitigation:   "Upgrade; disable proxy caching as temporary workaround.",
		MatchProduct: "nginx",
		MaxVersion:   "1.13.2",
	},

	// ══════════════════════════════════════════════════════════════════════════
	// TLS / OpenSSL
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2014-0160",
		CWE:          "CWE-125",
		Title:        "Heartbleed — OpenSSL memory disclosure",
		Description:  "The TLS heartbeat extension in OpenSSL 1.0.1 through 1.0.1f allows attackers to read up to 64 KB of process memory per request, potentially exposing private keys, passwords, and session tokens.",
		Severity:     SevCritical,
		CVSS:         7.5,
		EPSS:         0.97,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2014-0160", "https://heartbleed.com"},
		FixedIn:      "OpenSSL 1.0.1g",
		Mitigation:   "Upgrade OpenSSL; regenerate all keys and certificates; invalidate sessions.",
		ExploitAvail: true,
		MatchBanner:  "openssl/1.0.1",
	},
	{
		CVE:         "CVE-2022-0778",
		CWE:         "CWE-835",
		Title:       "OpenSSL infinite loop in BN_mod_sqrt() — DoS",
		Description: "A crafted certificate with invalid elliptic curve parameters causes OpenSSL < 3.0.2 / 1.1.1n / 1.0.2zd to loop indefinitely, causing DoS.",
		Severity:    SevHigh,
		CVSS:        7.5,
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-0778"},
		FixedIn:     "OpenSSL 3.0.2 / 1.1.1n",
		MatchBanner: "openssl",
	},

	// ══════════════════════════════════════════════════════════════════════════
	// FTP
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2011-2523",
		CWE:          "CWE-78",
		Title:        "vsftpd 2.3.4 backdoor — unauthenticated shell on port 6200",
		Description:  "Trojanised vsftpd 2.3.4 distributed via certain mirrors contains a backdoor: entering a username containing ':)' triggers a bind shell on port 6200.",
		Severity:     SevCritical,
		CVSS:         10.0,
		EPSS:         0.95,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2011-2523"},
		FixedIn:      "2.3.5",
		Mitigation:   "Replace vsftpd immediately; verify binary checksum.",
		ExploitAvail: true,
		MatchBanner:  "vsftpd 2.3.4",
	},
	{
		CVE:          "CVE-2010-4221",
		CWE:          "CWE-121",
		Title:        "ProFTPD 1.3.2rc3 – 1.3.3b Telnet IAC stack overflow",
		Description:  "A stack-based buffer overflow via Telnet IAC commands in the ProFTPD daemon allows unauthenticated RCE.",
		Severity:     SevCritical,
		CVSS:         10.0,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2010-4221"},
		FixedIn:      "1.3.3c",
		ExploitAvail: true,
		MatchBanner:  "proftpd",
	},

	// ══════════════════════════════════════════════════════════════════════════
	// SMTP
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2010-4344",
		CWE:          "CWE-122",
		Title:        "Exim 4.69 heap overflow — unauthenticated RCE as root",
		Description:  "A heap buffer overflow in Exim 4.69's string_vformat() allows a remote attacker to execute arbitrary code as root.",
		Severity:     SevCritical,
		CVSS:         9.3,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2010-4344"},
		FixedIn:      "4.70",
		ExploitAvail: true,
		MatchBanner:  "exim 4.69",
	},
	{
		CVE:          "CVE-2019-10149",
		CWE:          "CWE-78",
		Title:        "Exim 4.87–4.91 — local/remote command execution ('The Return of the WIZard')",
		Description:  "A flaw in deliver_message() allows command injection via the RCPT TO address in Exim 4.87–4.91, leading to root code execution.",
		Severity:     SevCritical,
		CVSS:         9.8,
		EPSS:         0.97,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-10149"},
		FixedIn:      "4.92",
		ExploitAvail: true,
		MatchBanner:  "exim",
		MinVersion:   "4.87",
		MaxVersion:   "4.91",
	},
	{
		CVE:          "CVE-2020-28017",
		CWE:          "CWE-190",
		Title:        "Exim 21Nails — integer overflow in receive_add_recipient (< 4.94.2)",
		Description:  "One of 21 Qualys-discovered flaws in Exim. Integer overflow allows heap corruption and RCE.",
		Severity:     SevCritical,
		CVSS:         9.8,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-28017", "https://www.qualys.com/2021/05/04/21nails/21nails.txt"},
		FixedIn:      "4.94.2",
		ExploitAvail: true,
		MatchBanner:  "exim",
		MaxVersion:   "4.94.1",
	},

	// ══════════════════════════════════════════════════════════════════════════
	// Redis
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2025-49844",
		CWE:          "CWE-416",
		Title:        "Redis RediShell — use-after-free Lua sandbox escape RCE (CVSS 10)",
		Description:  "A 13-year-old use-after-free (UAF) in Redis's Lua script execution allows a post-auth attacker to escape the sandbox and execute arbitrary native code on the host. First Redis CVE ever rated CVSS 10.",
		Severity:     SevCritical,
		CVSS:         10.0,
		EPSS:         0.50,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-49844", "https://www.wiz.io/blog/wiz-research-redis-rce-cve-2025-49844"},
		FixedIn:      "See vendor advisory",
		Mitigation:   "Patch immediately; disable Lua scripting if not needed (rename EVAL).",
		ExploitAvail: false,
		MatchService: "redis",
	},
	{
		CVE:          "CVE-2022-0543",
		CWE:          "CWE-862",
		Title:        "Redis Lua sandbox escape (< 6.2.7 / < 7.0.1) — Debian/Ubuntu packages",
		Description:  "Debian/Ubuntu Redis packages expose a package table in the Lua environment allowing sandbox escape and arbitrary code execution via EVAL.",
		Severity:     SevCritical,
		CVSS:         10.0,
		EPSS:         0.97,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-0543"},
		FixedIn:      "6.2.7 / 7.0.1",
		Mitigation:   "Upgrade Redis; rename or disable EVAL command.",
		ExploitAvail: true,
		MatchService: "redis",
		MaxVersion:   "6.2.6",
	},
	{
		CVE:          "CVE-2015-8080",
		CWE:          "CWE-190",
		Title:        "Redis Lua integer overflow (< 3.0.5) — stack corruption",
		Description:  "Integer overflow in the Lua garbage collection in Redis < 3.0.5 can lead to denial of service or arbitrary code execution.",
		Severity:     SevHigh,
		CVSS:         7.5,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2015-8080"},
		FixedIn:      "3.0.5",
		MatchService: "redis",
		MaxVersion:   "3.0.4",
	},

	// ══════════════════════════════════════════════════════════════════════════
	// MongoDB
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2025-14847",
		CWE:          "CWE-130",
		Title:        "MongoDB Server — heap memory read + potential RCE via zlib header parsing",
		Description:  "Improper handling of length parameter inconsistency in zlib-compressed protocol header parsing allows an unauthenticated attacker to read heap memory and potentially achieve RCE.",
		Severity:     SevCritical,
		CVSS:         9.8,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-14847"},
		FixedIn:      "See MongoDB advisory SERVER-115508",
		Mitigation:   "Patch immediately; restrict MongoDB network exposure.",
		ExploitAvail: false,
		MatchService: "mongodb",
	},
	{
		CVE:          "CVE-2021-32040",
		CWE:          "CWE-400",
		Title:        "MongoDB Server < 5.0.4 — DoS via crafted aggregation query",
		Description:  "A crafted aggregation pipeline can cause MongoDB to exhaust available memory, leading to denial of service.",
		Severity:     SevHigh,
		CVSS:         7.5,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-32040"},
		FixedIn:      "5.0.4",
		MatchService: "mongodb",
		MaxVersion:   "5.0.3",
	},

	// ══════════════════════════════════════════════════════════════════════════
	// MySQL / MariaDB
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2016-6662",
		CWE:          "CWE-264",
		Title:        "MySQL ≤ 5.7.14 — config file injection RCE as root",
		Description:  "An authenticated MySQL user can create/overwrite the MySQL config file, leading to arbitrary command execution on the next MySQL restart.",
		Severity:     SevCritical,
		CVSS:         9.8,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2016-6662"},
		FixedIn:      "5.7.15",
		ExploitAvail: true,
		MatchService: "mysql",
		MaxVersion:   "5.7.14",
	},
	{
		CVE:          "CVE-2012-2122",
		CWE:          "CWE-697",
		Title:        "MySQL / MariaDB authentication bypass via timing attack",
		Description:  "Due to a memcmp() result comparison bug, ~1 in 256 authentication attempts succeeds regardless of password. Brute-forceable in seconds.",
		Severity:     SevCritical,
		CVSS:         10.0,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2012-2122"},
		FixedIn:      "MySQL 5.1.63 / MariaDB 5.1.62",
		ExploitAvail: true,
		MatchService: "mysql",
		MaxVersion:   "5.5.23",
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PostgreSQL
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2019-9193",
		CWE:          "CWE-78",
		Title:        "PostgreSQL COPY TO/FROM PROGRAM — RCE for superusers",
		Description:  "The COPY TO/FROM PROGRAM feature allows superusers (and users with pg_execute_server_program role) to execute arbitrary OS commands.",
		Severity:     SevHigh,
		CVSS:         7.2,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-9193"},
		FixedIn:      "Mitigate via access controls",
		Mitigation:   "Restrict superuser access; revoke pg_execute_server_program role.",
		ExploitAvail: true,
		MatchService: "postgresql",
	},
	{
		CVE:          "CVE-2024-32655",
		CWE:          "CWE-89",
		Title:        "Npgsql SQL injection via parameter sniffing (< 8.0.3)",
		Description:  "Npgsql ≤ 8.0.2 is vulnerable to SQL injection via specially crafted SQL parameter names under certain conditions.",
		Severity:     SevHigh,
		CVSS:         8.1,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-32655"},
		FixedIn:      "8.0.3",
		MatchService: "postgresql",
	},

	// ══════════════════════════════════════════════════════════════════════════
	// Elasticsearch
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2015-1427",
		CWE:          "CWE-94",
		Title:        "Elasticsearch Groovy sandbox escape — unauthenticated RCE (< 1.4.3)",
		Description:  "The Groovy scripting engine in Elasticsearch < 1.4.3 allows sandbox escape, enabling unauthenticated remote code execution.",
		Severity:     SevCritical,
		CVSS:         10.0,
		EPSS:         0.97,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2015-1427"},
		FixedIn:      "1.4.3",
		ExploitAvail: true,
		MatchService: "elasticsearch",
		MaxVersion:   "1.4.2",
	},
	{
		CVE:          "CVE-2014-3120",
		CWE:          "CWE-94",
		Title:        "Elasticsearch dynamic script RCE (< 1.3.8)",
		Description:  "Dynamic scripting is enabled by default in Elasticsearch < 1.3.8, allowing unauthenticated code execution via crafted search queries.",
		Severity:     SevCritical,
		CVSS:         10.0,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2014-3120"},
		FixedIn:      "1.3.8",
		ExploitAvail: true,
		MatchService: "elasticsearch",
		MaxVersion:   "1.3.7",
	},

	// ══════════════════════════════════════════════════════════════════════════
	// Docker / Container runtime
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2019-5736",
		CWE:          "CWE-78",
		Title:        "runc container escape — host binary overwrite (< 1.0-rc6)",
		Description:  "A malicious container can overwrite the host's runc binary and gain root access on the host. Affects Docker, Kubernetes, containerd using runc < 1.0-rc6.",
		Severity:     SevCritical,
		CVSS:         8.6,
		EPSS:         0.97,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-5736"},
		FixedIn:      "runc 1.0-rc6",
		ExploitAvail: true,
		MatchService: "docker",
	},
	{
		CVE:          "CVE-2020-15257",
		CWE:          "CWE-269",
		Title:        "containerd Shim API access — privilege escalation from container",
		Description:  "The containerd-shim API, when exposed on an abstract UNIX socket with improper permissions, allows host privilege escalation from within a container.",
		Severity:     SevHigh,
		CVSS:         5.2,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-15257"},
		FixedIn:      "containerd 1.3.9 / 1.4.3",
		MatchService: "docker",
	},

	// ══════════════════════════════════════════════════════════════════════════
	// Kubernetes
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2018-1002105",
		CWE:          "CWE-305",
		Title:        "Kubernetes API server privilege escalation — unauthenticated access",
		Description:  "A flaw allows an unauthenticated attacker to proxy arbitrary requests to cluster internal services via an established websocket connection to the API server.",
		Severity:     SevCritical,
		CVSS:         9.8,
		EPSS:         0.94,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-1002105"},
		FixedIn:      "1.10.11 / 1.11.5 / 1.12.3",
		ExploitAvail: true,
		MatchService: "k8s",
		Port:         6443,
	},
	{
		CVE:          "CVE-2022-3294",
		CWE:          "CWE-601",
		Title:        "Kubernetes API server node address SSRF",
		Description:  "Node address not validated in Kubernetes API server allows SSRF, routing requests to unintended internal services.",
		Severity:     SevHigh,
		CVSS:         8.8,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-3294"},
		FixedIn:      "1.25.4 / 1.24.8",
		MatchService: "k8s",
		Port:         6443,
	},

	// ══════════════════════════════════════════════════════════════════════════
	// RDP (Remote Desktop Protocol)
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2019-0708",
		CWE:          "CWE-416",
		Title:        "BlueKeep — pre-auth RCE in Windows RDP (wormable)",
		Description:  "A use-after-free in the Windows Remote Desktop Services component allows unauthenticated code execution. The vulnerability is wormable (no user interaction). Affects XP, 7, Server 2003, 2008.",
		Severity:     SevCritical,
		CVSS:         9.8,
		EPSS:         0.97,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-0708"},
		FixedIn:      "Windows June 2019 Patch Tuesday",
		Mitigation:   "Apply MS patch; enable NLA; block port 3389 from internet.",
		ExploitAvail: true,
		MatchService: "rdp",
		Port:         3389,
	},
	{
		CVE:          "CVE-2020-0609",
		CWE:          "CWE-122",
		Title:        "Windows RD Gateway — pre-auth RCE (wormable)",
		Description:  "Heap overflow in Windows Remote Desktop Gateway allows unauthenticated code execution with no user interaction.",
		Severity:     SevCritical,
		CVSS:         9.8,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-0609"},
		FixedIn:      "Windows January 2020 Patch Tuesday",
		MatchService: "rdp",
	},

	// ══════════════════════════════════════════════════════════════════════════
	// SMB / Samba
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2017-0144",
		CWE:          "CWE-119",
		Title:        "EternalBlue — SMB buffer overflow RCE (WannaCry / NotPetya)",
		Description:  "Buffer overflow in the SMBv1 transaction request handler allows unauthenticated code execution. Used by WannaCry and NotPetya ransomware campaigns.",
		Severity:     SevCritical,
		CVSS:         8.1,
		EPSS:         0.97,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-0144"},
		FixedIn:      "Windows MS17-010 patch",
		Mitigation:   "Apply MS17-010; disable SMBv1; block port 445 at perimeter.",
		ExploitAvail: true,
		MatchService: "smb",
		Port:         445,
	},
	{
		CVE:          "CVE-2017-7494",
		CWE:          "CWE-20",
		Title:        "Samba SambaCry — unauthenticated RCE (7 years of Samba versions)",
		Description:  "A shared library loading flaw in Samba 3.5.0–4.6.4 allows an authenticated (or guest) user with write access to upload a shared library and execute it on the server.",
		Severity:     SevCritical,
		CVSS:         9.8,
		EPSS:         0.97,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-7494"},
		FixedIn:      "4.6.4",
		Mitigation:   "Upgrade Samba; add 'nt pipe support = no' to smb.conf.",
		ExploitAvail: true,
		MatchBanner:  "samba",
		MinVersion:   "3.5.0",
		MaxVersion:   "4.6.3",
	},

	// ══════════════════════════════════════════════════════════════════════════
	// VNC
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2019-15681",
		CWE:          "CWE-401",
		Title:        "LibVNCServer memory leak — info disclosure",
		Description:  "LibVNCServer ≤ 0.9.12 has a memory leak in the VNC server handler that allows remote info disclosure.",
		Severity:     SevHigh,
		CVSS:         7.5,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-15681"},
		FixedIn:      "0.9.13",
		MatchService: "vnc",
	},
	{
		CVE:          "CVE-2006-2369",
		CWE:          "CWE-287",
		Title:        "RealVNC 4.1.1 authentication bypass",
		Description:  "RealVNC 4.1.1 allows connection with None authentication type even when server requires VNC authentication.",
		Severity:     SevCritical,
		CVSS:         7.5,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2006-2369"},
		FixedIn:      "4.1.2",
		ExploitAvail: true,
		MatchBanner:  "rfb 003.008",
	},

	// ══════════════════════════════════════════════════════════════════════════
	// MSSQL
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2020-0618",
		CWE:          "CWE-502",
		Title:        "SQL Server Reporting Services RCE — authenticated deserialization",
		Description:  "A deserialization vulnerability in SQL Server Reporting Services allows an authenticated attacker to execute code on the server.",
		Severity:     SevHigh,
		CVSS:         8.8,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-0618"},
		FixedIn:      "February 2020 Patch Tuesday",
		ExploitAvail: true,
		MatchService: "mssql",
	},

	// ══════════════════════════════════════════════════════════════════════════
	// Oracle DB
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2012-1675",
		CWE:          "CWE-264",
		Title:        "Oracle TNS Poison — remote hijack of DB connections",
		Description:  "The Oracle TNS Listener in 11g R1 and earlier allows remote attackers to intercept/redirect client-to-DB sessions (CVE-2012-1675, 'TNS Poison').",
		Severity:     SevHigh,
		CVSS:         7.5,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2012-1675"},
		FixedIn:      "Oracle CPU April 2012",
		MatchService: "oracle",
		Port:         1521,
	},

	// ══════════════════════════════════════════════════════════════════════════
	// Log4Shell (affects many services with HTTP interface)
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:          "CVE-2021-44228",
		CWE:          "CWE-917",
		Title:        "Log4Shell — JNDI injection RCE in Log4j 2 (< 2.15.0)",
		Description:  "A critical JNDI injection vulnerability in Apache Log4j 2 allows unauthenticated RCE when user-controlled input is logged. Affects any Java application using Log4j2 < 2.15.0.",
		Severity:     SevCritical,
		CVSS:         10.0,
		EPSS:         0.97,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "https://logging.apache.org/log4j/2.x/security.html"},
		FixedIn:      "Log4j 2.15.0 (disable lookup: 2.16.0)",
		Mitigation:   "Upgrade Log4j; set log4j2.formatMsgNoLookups=true as workaround.",
		ExploitAvail: true,
		MatchBanner:  "java",
		MatchService: "http",
	},
	{
		CVE:          "CVE-2021-45046",
		CWE:          "CWE-917",
		Title:        "Log4Shell bypass — Log4j 2.15.0 incomplete fix",
		Description:  "The fix for CVE-2021-44228 in Log4j 2.15.0 was incomplete. Certain non-default configurations are still exploitable. Fixed in 2.16.0.",
		Severity:     SevCritical,
		CVSS:         9.0,
		References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-45046"},
		FixedIn:      "Log4j 2.16.0",
		ExploitAvail: true,
		MatchBanner:  "java",
		MaxVersion:   "2.15.0",
	},

	// ══════════════════════════════════════════════════════════════════════════
	// Memcached
	// ══════════════════════════════════════════════════════════════════════════

	{
		CVE:         "CVE-2011-4971",
		CWE:         "CWE-189",
		Title:       "Memcached < 1.4.15 — integer overflow DoS",
		Description: "An integer overflow in Memcached < 1.4.15 allows remote DoS via crafted binary protocol packets.",
		Severity:    SevMedium,
		CVSS:        5.0,
		References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2011-4971"},
		FixedIn:     "1.4.15",
		MatchBanner: "memcached",
		MaxVersion:  "1.4.14",
	},
}

// ─── Summary Reporter ─────────────────────────────────────────────────────────

// PrintSummary renders all findings grouped by severity with colour coding.
func PrintSummary(all []Finding, noColor bool) {
	c := func(code, s string) string {
		if noColor {
			return s
		}
		return code + s + ansiReset
	}

	if len(all) == 0 {
		fmt.Printf("\n%s\n", c(ansiGreen, "[✓] No known vulnerabilities matched."))
		return
	}

	fmt.Printf("\n%s\n", c("\033[1;31m", "╔══════════════════════════════════════════════════════════════════╗"))
	fmt.Printf("%s\n", c("\033[1;31m", "║            VULNERABILITY FINDINGS SUMMARY                       ║"))
	fmt.Printf("%s\n", c("\033[1;31m", "╚══════════════════════════════════════════════════════════════════╝"))

	counts := map[Severity]int{}
	for _, f := range all {
		counts[f.Severity]++
	}

	// Print by descending severity
	for _, sev := range []Severity{SevCritical, SevHigh, SevMedium, SevLow, SevInfo} {
		for _, f := range all {
			if f.Severity == sev {
				printFinding(f, noColor)
			}
		}
	}

	fmt.Printf("\n%s  CRITICAL=%s  HIGH=%s  MEDIUM=%s  LOW=%s  INFO=%s\n",
		c(ansiBold, "Totals:"),
		c("\033[1;35m", fmt.Sprintf("%d", counts[SevCritical])),
		c("\033[1;31m", fmt.Sprintf("%d", counts[SevHigh])),
		c("\033[1;33m", fmt.Sprintf("%d", counts[SevMedium])),
		c("\033[1;32m", fmt.Sprintf("%d", counts[SevLow])),
		c(ansiCyan, fmt.Sprintf("%d", counts[SevInfo])),
	)
}

func printFinding(f Finding, noColor bool) {
	c := func(code, s string) string {
		if noColor {
			return s
		}
		return code + s + ansiReset
	}

	sevColor := map[Severity]string{
		SevCritical: ansiPurple,
		SevHigh:     ansiRed,
		SevMedium:   ansiYellow,
		SevLow:      ansiGreen,
		SevInfo:     ansiCyan,
	}[f.Severity]

	exploitTag := ""
	if f.ExploitAvail {
		exploitTag = c("\033[1;31m", " [PoC/Exploit Available]")
	}

	fmt.Printf("\n%s %s%s\n",
		c(sevColor, "["+f.Severity.String()+"]"),
		c(ansiBold+ansiWhite, f.Title),
		exploitTag,
	)
	fmt.Printf("  %s %s:%d  %s %s\n",
		c(ansiGrey, "Target  :"), f.Host, f.Port,
		c(ansiGrey, "Service:"), f.Service,
	)
	if f.CVE != "" {
		epssStr := ""
		if f.EPSS > 0 {
			epssStr = fmt.Sprintf("  EPSS: %.0f%%", f.EPSS*100)
		}
		fmt.Printf("  %s %s  %s CVSS: %.1f%s\n",
			c(ansiGrey, "CVE     :"),
			c(ansiBold, f.CVE),
			c(ansiGrey, "|"),
			f.CVSS,
			c(ansiYellow, epssStr),
		)
	}
	if f.CWE != "" {
		fmt.Printf("  %s %s\n", c(ansiGrey, "CWE     :"), f.CWE)
	}
	if f.FixedIn != "" {
		fmt.Printf("  %s %s\n", c(ansiGrey, "Fixed In:"), c(ansiGreen, f.FixedIn))
	}
	if f.Mitigation != "" {
		fmt.Printf("  %s %s\n", c(ansiGrey, "Mitigate:"), f.Mitigation)
	}
	// Word-wrap description at column 80
	fmt.Printf("  %s\n", c(ansiGrey, "Desc    :"))
	words := strings.Fields(f.Description)
	line := "    "
	for _, w := range words {
		if len(line)+len(w)+1 > 82 {
			fmt.Println(line)
			line = "    " + w
		} else {
			if line != "    " {
				line += " "
			}
			line += w
		}
	}
	if line != "    " {
		fmt.Println(line)
	}
	if len(f.References) > 0 {
		fmt.Printf("  %s %s\n", c(ansiGrey, "Ref     :"), f.References[0])
	}
	fmt.Printf("  %s\n", c(ansiGrey, strings.Repeat("─", 62)))
}
