// pkg/banner/display.go
// Rich, human-friendly terminal rendering of ServiceInfo.
// Uses ANSI colour codes directly (no external dep beyond aurora which
// Naabu already imports) so it compiles without adding deps.

package banner

import (
	"fmt"
	"strings"
)

// ANSI helpers (kept internal; you can swap in aurora if you prefer).
const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	white  = "\033[97m"
	grey   = "\033[90m"
	bgRed  = "\033[41m"
)

// Print renders a single ServiceInfo to stdout in a structured, coloured block.
// Call this once per port after Grab() returns.
func Print(si *ServiceInfo, noColor bool) {
	if noColor {
		printPlain(si)
		return
	}
	printColor(si)
}

func printColor(si *ServiceInfo) {
	// ── header line ─────────────────────────────────────────────────────────
	tlsTag := ""
	if si.TLS {
		tlsTag = green + " [TLS]" + reset
	}

	fmt.Printf("\n%s┌─ %s%s:%d%s%s%s [%s]%s\n",
		cyan, bold+white, si.Host, si.Port, reset,
		tlsTag,
		grey, si.Protocol, reset,
		grey,
	)

	// ── service / product ────────────────────────────────────────────────────
	svcColor := cyan
	if si.ServiceName == "Unknown" {
		svcColor = grey
	}
	fmt.Printf("%s│%s  %-14s %s%s%s",
		cyan, reset,
		"Service:",
		svcColor+bold, si.ServiceName, reset,
	)
	if si.Product != "" && si.Product != si.ServiceName {
		fmt.Printf("  (%s%s%s)", yellow, si.Product, reset)
	}
	fmt.Println()

	// ── version ──────────────────────────────────────────────────────────────
	if si.Version != "" {
		fmt.Printf("%s│%s  %-14s %s%s%s\n",
			cyan, reset, "Version:", green, si.Version, reset)
	}

	// ── OS hint ──────────────────────────────────────────────────────────────
	if si.OS != "" {
		fmt.Printf("%s│%s  %-14s %s%s%s\n",
			cyan, reset, "OS Hint:", yellow, si.OS, reset)
	}

	// ── extra info ───────────────────────────────────────────────────────────
	if si.ExtraInfo != "" {
		fmt.Printf("%s│%s  %-14s %s%s%s\n",
			cyan, reset, "Info:", grey, si.ExtraInfo, reset)
	}

	// ── confidence ───────────────────────────────────────────────────────────
	confColor := green
	confLabel := "High"
	if si.Confidence < 60 {
		confColor = yellow
		confLabel = "Medium"
	}
	if si.Confidence < 40 {
		confColor = red
		confLabel = "Low"
	}
	fmt.Printf("%s│%s  %-14s %s%d%% (%s)%s\n",
		cyan, reset, "Confidence:", confColor, si.Confidence, confLabel, reset)

	// ── raw banner (folded to 80 chars) ──────────────────────────────────────
	if si.RawBanner != "" {
		fmt.Printf("%s│%s  %-14s\n", cyan, reset, "Banner:")
		for _, line := range foldLines(si.RawBanner, 72) {
			fmt.Printf("%s│%s    %s%s%s\n", cyan, reset, grey, line, reset)
		}
	}

	// ── timing ───────────────────────────────────────────────────────────────
	fmt.Printf("%s│%s  %-14s %s%s%s\n",
		cyan, reset, "Grab time:", grey, si.GrabTime.Round(1*1000000), reset) // round to ms

	fmt.Printf("%s└%s%s\n", cyan, strings.Repeat("─", 60), reset)
}

func printPlain(si *ServiceInfo) {
	tlsTag := ""
	if si.TLS {
		tlsTag = " [TLS]"
	}
	fmt.Printf("\n┌─ %s:%d%s [%s]\n", si.Host, si.Port, tlsTag, si.Protocol)
	fmt.Printf("│  %-14s %s\n", "Service:", si.ServiceName)
	if si.Product != "" && si.Product != si.ServiceName {
		fmt.Printf("│  %-14s %s\n", "Product:", si.Product)
	}
	if si.Version != "" {
		fmt.Printf("│  %-14s %s\n", "Version:", si.Version)
	}
	if si.OS != "" {
		fmt.Printf("│  %-14s %s\n", "OS Hint:", si.OS)
	}
	if si.ExtraInfo != "" {
		fmt.Printf("│  %-14s %s\n", "Info:", si.ExtraInfo)
	}
	if si.RawBanner != "" {
		fmt.Printf("│  Banner:\n")
		for _, line := range foldLines(si.RawBanner, 72) {
			fmt.Printf("│    %s\n", line)
		}
	}
	fmt.Printf("└%s\n", strings.Repeat("─", 60))
}

// foldLines wraps raw at width, splitting only on actual newlines in the string.
func foldLines(raw string, width int) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		for len(line) > width {
			out = append(out, line[:width])
			line = line[width:]
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
