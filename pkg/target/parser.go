// pkg/target/parser.go
// Normalises the many forms a user might specify a target into a
// canonical (host, port) pair that Naabu can understand.
//
// Supported input formats
// ───────────────────────
//   192.168.1.1            → host only, no port override
//   192.168.1.1:8080       → host + explicit port
//   http://example.com     → scheme → derive port 80
//   https://example.com    → scheme → derive port 443
//   https://example.com:8443/path → host + explicit port
//   example.com            → hostname only
//   192.168.1.0/24         → CIDR block (returned as-is for Naabu)

package target

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Target represents one parsed scan target.
type Target struct {
	Raw      string // original string the user provided
	Host     string // hostname or IP (no port)
	IP       string // resolved IP (may be empty until resolved)
	Port     int    // explicit port, 0 if none specified
	Scheme   string // "http", "https", or ""
	IsCIDR   bool   // true if it was a CIDR notation
	Original string // same as Raw; handy alias
}

// Parse converts a raw target string into a Target.
// It never performs DNS lookups.
func Parse(raw string) (*Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty target")
	}

	t := &Target{Raw: raw, Original: raw}

	// ── CIDR ────────────────────────────────────────────────────────────────
	if _, _, err := net.ParseCIDR(raw); err == nil {
		t.Host = raw
		t.IsCIDR = true
		return t, nil
	}

	// ── URL with scheme ──────────────────────────────────────────────────────
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid URL %q: %w", raw, err)
		}
		t.Scheme = u.Scheme
		hostname := u.Hostname()
		portStr := u.Port()

		if portStr != "" {
			p, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, fmt.Errorf("invalid port in %q: %w", raw, err)
			}
			t.Port = p
		} else {
			t.Port = defaultPortForScheme(u.Scheme)
		}
		t.Host = hostname
		return t, nil
	}

	// ── host:port (no scheme) ────────────────────────────────────────────────
	// Be careful: IPv6 addresses look like [::1]:80
	if h, p, err := net.SplitHostPort(raw); err == nil {
		port, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port in %q: %w", raw, err)
		}
		t.Host = h
		t.Port = port
		return t, nil
	}

	// ── plain IP or hostname ─────────────────────────────────────────────────
	t.Host = raw
	return t, nil
}

// ParseAll parses a list of raw target strings and returns the valid ones.
// Errors are collected and returned alongside valid targets.
func ParseAll(raws []string) ([]*Target, []error) {
	var targets []*Target
	var errs []error
	seen := map[string]bool{}
	for _, r := range raws {
		t, err := Parse(r)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		key := t.Host + ":" + strconv.Itoa(t.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		targets = append(targets, t)
	}
	return targets, errs
}

// NaabuHostArgs converts a slice of Targets into the format Naabu expects.
// Targets with explicit ports have their port stored in ExplicitPorts.
func NaabuHostArgs(targets []*Target) (hosts []string, explicitPorts map[string]int) {
	explicitPorts = map[string]int{}
	for _, t := range targets {
		hosts = append(hosts, t.Host)
		if t.Port > 0 {
			explicitPorts[t.Host] = t.Port
		}
	}
	return
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func defaultPortForScheme(scheme string) int {
	switch strings.ToLower(scheme) {
	case "https":
		return 443
	case "http":
		return 80
	case "ftp":
		return 21
	case "ftps":
		return 990
	case "ssh":
		return 22
	case "smtp":
		return 25
	case "smtps":
		return 465
	}
	return 0
}
