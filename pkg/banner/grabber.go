// pkg/banner/grabber.go
// Enhanced banner grabbing with protocol detection, service fingerprinting,
// and structured output for every open port discovered by Naabu.

package banner

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// ─── Data Structures ─────────────────────────────────────────────────────────

// ServiceInfo holds everything we learn from a single port's banner.
type ServiceInfo struct {
	Host        string        // resolved hostname or IP
	IP          string        // resolved IP address
	Port        int           // port number
	Protocol    string        // "tcp" | "udp"
	TLS         bool          // whether TLS was negotiated
	ServiceName string        // e.g. "HTTP", "SSH", "SMTP" …
	Product     string        // e.g. "Apache httpd", "OpenSSH"
	Version     string        // e.g. "2.4.51", "8.9p1"
	OS          string        // OS hint from banner
	RawBanner   string        // first 512 bytes, printable
	ExtraInfo   string        // any extra detail (HTTP Server header, SSH comment, …)
	Confidence  int           // 0–100 how confident we are about detection
	GrabTime    time.Duration // how long the grab took
}

// ─── Port → Protocol Heuristics ──────────────────────────────────────────────

// wellKnown maps common ports to their expected application protocol.
// Used to decide which probe to send before any banner arrives.
var wellKnown = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	143:   "IMAP",
	443:   "HTTPS",
	465:   "SMTPS",
	587:   "SMTP",
	993:   "IMAPS",
	995:   "POP3S",
	1433:  "MSSQL",
	1521:  "Oracle",
	2375:  "DockerHTTP",
	2376:  "DockerHTTPS",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	5984:  "CouchDB",
	6379:  "Redis",
	6443:  "K8sAPI",
	8080:  "HTTP",
	8443:  "HTTPS",
	8888:  "HTTP",
	9200:  "Elasticsearch",
	9300:  "Elasticsearch",
	27017: "MongoDB",
}

// ─── Public Entry Point ───────────────────────────────────────────────────────

// Grab connects to host:port, selects the right probe strategy, and
// returns a populated ServiceInfo. It never panics.
func Grab(host, ip string, port int, proto string, isTLS bool, timeout time.Duration) *ServiceInfo {
	start := time.Now()

	si := &ServiceInfo{
		Host:     host,
		IP:       ip,
		Port:     port,
		Protocol: proto,
		TLS:      isTLS,
	}

	if proto == "udp" {
		// UDP: minimal heuristic only
		si.ServiceName = guessServiceName(port, "")
		si.Confidence = 30
		si.GrabTime = time.Since(start)
		return si
	}

	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))

	// Decide TLS automatically for well-known TLS ports even if caller didn't say so
	if port == 443 || port == 8443 || port == 465 || port == 993 || port == 995 || port == 2376 || port == 6443 {
		isTLS = true
		si.TLS = true
	}

	// Try HTTP(S) first for web ports — gives us much richer info
	guessed := wellKnown[port]
	if guessed == "HTTP" || guessed == "HTTPS" || port == 80 || port == 443 || port == 8080 || port == 8443 || port == 8888 {
		if h := grabHTTP(addr, isTLS, timeout); h != nil {
			si.ServiceName = h.ServiceName
			si.Product = h.Product
			si.Version = h.Version
			si.RawBanner = h.RawBanner
			si.ExtraInfo = h.ExtraInfo
			si.Confidence = h.Confidence
			si.GrabTime = time.Since(start)
			return si
		}
	}

	// Generic TCP read (works for SSH, FTP, SMTP, Redis, …)
	raw, err := grabTCP(addr, isTLS, timeout)
	if err == nil && len(raw) > 0 {
		si.RawBanner = sanitize(raw)
		si.ServiceName, si.Product, si.Version, si.OS, si.ExtraInfo, si.Confidence =
			parseRawBanner(si.RawBanner, port)
	} else {
		si.ServiceName = guessServiceName(port, "")
		si.Confidence = 20
	}

	si.GrabTime = time.Since(start)
	return si
}

// ─── HTTP / HTTPS Grabber ─────────────────────────────────────────────────────

type httpResult struct {
	ServiceName string
	Product     string
	Version     string
	RawBanner   string
	ExtraInfo   string
	Confidence  int
}

func grabHTTP(addr string, useTLS bool, timeout time.Duration) *httpResult {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(fmt.Sprintf("%s://%s/", scheme, addr))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	server := resp.Header.Get("Server")
	xPoweredBy := resp.Header.Get("X-Powered-By")
	via := resp.Header.Get("Via")

	banner := fmt.Sprintf("%s %s\nServer: %s\nX-Powered-By: %s\nVia: %s",
		resp.Proto, resp.Status, server, xPoweredBy, via)

	product, version := parseServerHeader(server)

	extra := fmt.Sprintf("Status: %d | Title: (grab with full page read) | X-Powered-By: %s", resp.StatusCode, xPoweredBy)
	if via != "" {
		extra += " | Via: " + via
	}

	svc := "HTTP"
	if useTLS {
		svc = "HTTPS"
	}

	return &httpResult{
		ServiceName: svc,
		Product:     product,
		Version:     version,
		RawBanner:   sanitize(banner),
		ExtraInfo:   extra,
		Confidence:  85,
	}
}

// parseServerHeader extracts product+version from an HTTP Server header.
// "Apache/2.4.51 (Unix)" → ("Apache httpd", "2.4.51")
func parseServerHeader(s string) (product, version string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	parts := strings.SplitN(s, "/", 2)
	product = parts[0]
	if len(parts) == 2 {
		vRest := strings.SplitN(parts[1], " ", 2)
		version = vRest[0]
	}
	return
}

// ─── Raw TCP / TLS Banner Grabber ─────────────────────────────────────────────

func grabTCP(addr string, useTLS bool, timeout time.Duration) (string, error) {
	var conn net.Conn
	var err error

	dialer := &net.Dialer{Timeout: timeout}

	if useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout))

	// Some services (FTP, SSH, SMTP) send a banner immediately.
	// Others (HTTP) need a probe.
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 4096)

	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) >= 5 {
			break
		}
	}
	return strings.Join(lines, "\n"), nil
}

// ─── Raw Banner Parser ────────────────────────────────────────────────────────

// parseRawBanner does regex-free heuristic matching for the most common
// service banners encountered in the wild.
func parseRawBanner(raw string, port int) (svc, product, version, os, extra string, confidence int) {
	lower := strings.ToLower(raw)

	switch {
	// SSH
	case strings.HasPrefix(raw, "SSH-"):
		// SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
		svc = "SSH"
		confidence = 95
		parts := strings.SplitN(raw, "-", 3)
		if len(parts) >= 3 {
			rest := parts[2]
			sp := strings.SplitN(rest, " ", 2)
			product = sp[0] // e.g. OpenSSH_8.9p1
			if len(sp) > 1 {
				os = sp[1]
				extra = sp[1]
			}
			// version extraction from product
			idx := strings.Index(product, "_")
			if idx >= 0 {
				version = product[idx+1:]
				product = product[:idx] // "OpenSSH"
			}
		}
	// FTP
	case strings.HasPrefix(raw, "220 ") && strings.Contains(lower, "ftp"):
		svc = "FTP"
		product = extractAfter(raw, "220 ")
		confidence = 85
	case strings.HasPrefix(raw, "220-") || strings.HasPrefix(raw, "220 "):
		svc = "FTP/SMTP"
		product = extractAfter(raw, "220 ")
		confidence = 60
	// SMTP
	case strings.Contains(lower, "smtp") || strings.Contains(lower, "esmtp"):
		svc = "SMTP"
		confidence = 90
		product = extractAfter(raw, "220 ")
	// Redis
	case strings.HasPrefix(raw, "-ERR") || strings.Contains(lower, "redis"):
		svc = "Redis"
		confidence = 80
	// MongoDB
	case strings.Contains(lower, "mongodb") || strings.Contains(lower, "ismaster"):
		svc = "MongoDB"
		confidence = 75
	// MySQL/MariaDB — they send a binary handshake but the greeting often has ASCII fragments
	case strings.Contains(lower, "mysql") || strings.Contains(lower, "mariadb"):
		svc = "MySQL/MariaDB"
		confidence = 80
	// PostgreSQL — auth request
	case strings.Contains(lower, "postgresql"):
		svc = "PostgreSQL"
		confidence = 75
	// Elasticsearch
	case strings.Contains(lower, "elasticsearch") || strings.Contains(lower, `"cluster_name"`):
		svc = "Elasticsearch"
		confidence = 85
	// VNC
	case strings.HasPrefix(raw, "RFB "):
		svc = "VNC"
		version = extractAfter(raw, "RFB ")
		confidence = 95
	// Telnet
	case port == 23:
		svc = "Telnet"
		confidence = 50
	default:
		svc = guessServiceName(port, raw)
		confidence = 30
	}

	if product == "" {
		product = svc
	}
	return
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func guessServiceName(port int, _ string) string {
	if name, ok := wellKnown[port]; ok {
		return name
	}
	return "Unknown"
}

func extractAfter(s, prefix string) string {
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return s
	}
	rest := s[idx+len(prefix):]
	if nl := strings.IndexAny(rest, "\r\n"); nl >= 0 {
		return rest[:nl]
	}
	return rest
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 || r == '\n' || r == '\r' || r == '\t' {
			b.WriteRune(r)
		} else {
			b.WriteRune('.')
		}
	}
	result := b.String()
	if len(result) > 512 {
		return result[:512]
	}
	return result
}
