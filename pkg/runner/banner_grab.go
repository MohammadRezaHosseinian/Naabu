package runner

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
)

const (
	bannerReadTimeout = 2 * time.Second
	maxBannerSize     = 2048
	maxHTTPBody       = 8192
)

func grabProtocolBanner(ip string, port int, proto protocol.Protocol, timeout time.Duration) string {
	switch proto {
	case protocol.TCP:
		if port == 443 || port == 8443 {
			if banner := grabHTTPSBannerWithBody(ip, port, timeout); banner != "" {
				return banner
			}
		}
		return grabTCPBanner(ip, port, timeout)

	case protocol.UDP:
		if port == 53 {
			return grabDNSParsedBanner(ip, port, timeout)
		}
		return grabUDPBanner(ip, port, timeout)

	default:
		return ""
	}
}

func grabTCPBanner(ip string, port int, timeout time.Duration) string {
	addr := net.JoinHostPort(ip, fmt.Sprint(port))

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(bannerReadTimeout))

	buf := make([]byte, 4096)

	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		data := buf[:n]
		service := detectTCPService(data, port)

		result := fmt.Sprintf("[%s] [Length: %d]", service, n)

		info := parseTCPBanner(data, service)
		if info != "" {
			result += " " + info
		}

		if service == "TCP" {
			preview := cleanBannerPreview(data, 80)
			if preview != "" {
				result += fmt.Sprintf(" [Data: %s]", preview)
			}
		}

		return result
	}

	probe := getTCPProbe(port)
	if probe != "" {
		conn.SetWriteDeadline(time.Now().Add(timeout))
		_, err := conn.Write([]byte(probe))
		if err == nil {
			conn.SetReadDeadline(time.Now().Add(bannerReadTimeout))

			n, err := conn.Read(buf)
			if err == nil && n > 0 {
				data := buf[:n]
				service := detectTCPService(data, port)

				result := fmt.Sprintf("[%s] [Length: %d]", service, n)

				info := parseTCPBanner(data, service)
				if info != "" {
					result += " " + info
				}

				if service == "TCP" {
					preview := cleanBannerPreview(data, 80)
					if preview != "" {
						result += fmt.Sprintf(" [Data: %s]", preview)
					}
				}

				return result
			}
		}
	}

	return httpProbeWithBody(conn, ip, timeout)
}

func getTCPProbe(port int) string {
	switch port {

	case 25, 587:
		return "EHLO scanner\r\n"

	case 110:
		return "USER test\r\n"

	case 143:
		return "A001 CAPABILITY\r\n"

	case 21:
		return "USER anonymous\r\n"

	case 6379:
		return "PING\r\n"

	case 11211:
		return "stats\r\n"

	case 9200:
		return "GET / HTTP/1.0\r\n\r\n"

	default:
		return ""
	}
}

func detectTCPService(b []byte, port int) string {
	s := string(b)

	if strings.HasPrefix(s, "SSH-") {
		return "SSH"
	}

	if strings.HasPrefix(s, "220") && strings.Contains(s, "FTP") {
		return "FTP"
	}

	if strings.HasPrefix(s, "220") && (strings.Contains(s, "SMTP") || strings.Contains(s, "ESMTP")) {
		return "SMTP"
	}

	if strings.HasPrefix(s, "+OK") {
		return "POP3"
	}

	if strings.Contains(s, "IMAP") || strings.HasPrefix(s, "* OK") {
		return "IMAP"
	}

	if strings.HasPrefix(s, "+PONG") || strings.Contains(s, "Redis") {
		return "Redis"
	}

	if len(b) > 5 && b[4] == 0x0a {
		return "MySQL"
	}

	if bytes.Contains(b, []byte("RFB ")) {
		return "VNC"
	}

	if port == 23 && len(b) > 0 && b[0] == 0xff {
		return "Telnet"
	}

	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25:
		return "SMTP"
	case 110:
		return "POP3"
	case 143:
		return "IMAP"
	case 3306:
		return "MySQL"
	case 5432:
		return "PostgreSQL"
	case 6379:
		return "Redis"
	}

	return "TCP"
}

func parseTCPBanner(b []byte, service string) string {
	s := strings.TrimSpace(string(b))
	lines := strings.Split(s, "\n")
	first := strings.TrimSpace(lines[0])

	switch service {

	case "SSH":
		parts := strings.Fields(first)
		if len(parts) >= 1 {
			version := strings.TrimPrefix(parts[0], "SSH-")
			if len(parts) > 1 {
				return fmt.Sprintf("[Version: %s] [Server: %s]", version, strings.Join(parts[1:], " "))
			}
			return fmt.Sprintf("[Version: %s]", version)
		}

	case "FTP", "SMTP":
		if len(first) > 4 {
			return fmt.Sprintf("[Banner: %s]", truncate(first[4:], 60))
		}

	case "POP3", "IMAP":
		return fmt.Sprintf("[Banner: %s]", truncate(first, 60))
	}

	return ""
}

func cleanBannerPreview(b []byte, max int) string {
	s := strings.TrimSpace(string(b))
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")

	if len(s) > max {
		s = s[:max] + "..."
	}

	return s
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)

	if len(s) > max {
		return s[:max] + "..."
	}

	return s
}

func httpProbeWithBody(conn net.Conn, host string, timeout time.Duration) string {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		log.Printf("[DEBUG] NewRequest error for %s: %v", host, err)
		return ""
	}

	req.Host = host
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Connection", "close")

	conn.SetDeadline(time.Now().Add(timeout))

	if err := req.Write(conn); err != nil {
		log.Printf("[DEBUG] Write error for %s: %v", host, err)
		return ""
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		log.Printf("[DEBUG] ReadResponse error for %s: %v", host, err)
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		log.Printf("[DEBUG] ReadAll error for %s: %v", host, err)
		return ""
	}

	title := extractTitle(body)
	contentLength := resp.ContentLength
	if contentLength == -1 {
		contentLength = int64(len(body))
	}

	server := resp.Header.Get("Server")
	contentType := resp.Header.Get("Content-Type")
	poweredBy := resp.Header.Get("X-Powered-By")

	result := fmt.Sprintf("[%s %d %s]", resp.Proto, resp.StatusCode, http.StatusText(resp.StatusCode))
	result += fmt.Sprintf(" [Length: %d]", contentLength)

	if server != "" {
		result += fmt.Sprintf(" [Server: %s]", server)
	}
	if contentType != "" {
		result += fmt.Sprintf(" [Content-Type: %s]", contentType)
	}
	if poweredBy != "" {
		result += fmt.Sprintf(" [X-Powered-By: %s]", poweredBy)
	}
	if title != "" {
		result += fmt.Sprintf(" [Title: %s]", title)
	}

	log.Printf("[DEBUG] Success for %s: %s", host, result)
	return result
}

func grabHTTPSBannerWithBody(ip string, port int, timeout time.Duration) string {
	addr := net.JoinHostPort(ip, fmt.Sprint(port))

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return ""
	}
	defer conn.Close()

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		return ""
	}

	req.Host = ip
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Connection", "close")

	conn.SetDeadline(time.Now().Add(timeout))

	if err := req.Write(conn); err != nil {
		return ""
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		log.Printf("[DEBUG] ReadResponse error for %s: %v", addr, err)

		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return ""
	}

	title := extractTitle(body)
	contentLength := resp.ContentLength
	if contentLength == -1 {
		contentLength = int64(len(body))
	}

	server := resp.Header.Get("Server")
	contentType := resp.Header.Get("Content-Type")
	poweredBy := resp.Header.Get("X-Powered-By")

	result := fmt.Sprintf("[%s %d %s]", resp.Proto, resp.StatusCode, http.StatusText(resp.StatusCode))
	result += fmt.Sprintf(" [Length: %d]", contentLength)

	if server != "" {
		result += fmt.Sprintf(" [Server: %s]", server)
	}
	if contentType != "" {
		result += fmt.Sprintf(" [Content-Type: %s]", contentType)
	}
	if poweredBy != "" {
		result += fmt.Sprintf(" [X-Powered-By: %s]", poweredBy)
	}
	if title != "" {
		result += fmt.Sprintf(" [Title: %s]", title)
	}

	return result
}

func extractTitle(body []byte) string {
	bodyStr := string(body)

	// Case-insensitive search for <title> tag
	startIdx := strings.Index(strings.ToLower(bodyStr), "<title>")
	if startIdx == -1 {
		return ""
	}
	startIdx += 7 // length of "<title>"

	endIdx := strings.Index(strings.ToLower(bodyStr[startIdx:]), "</title>")
	if endIdx == -1 {
		return ""
	}

	title := strings.TrimSpace(bodyStr[startIdx : startIdx+endIdx])

	// Limit title length and remove newlines/extra spaces
	title = strings.Join(strings.Fields(title), " ")
	if len(title) > 100 {
		title = title[:97] + "..."
	}

	return title
}

func grabDNSParsedBanner(ip string, port int, timeout time.Duration) string {
	m := new(dns.Msg)
	m.SetQuestion("google.com.", dns.TypeA)
	m.RecursionDesired = true

	data, err := m.Pack()
	if err != nil {
		return ""
	}

	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, fmt.Sprint(port)), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(data); err != nil {
		return ""
	}

	reply := make([]byte, 512)
	n, err := conn.Read(reply)
	if err != nil || n < 12 {
		return ""
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(reply[:n]); err != nil {
		return fmt.Sprintf("[DNS] [Malformed] [Length: %d]", n)
	}

	rcode := dns.RcodeToString[resp.MsgHdr.Rcode]
	result := fmt.Sprintf("[DNS] [Rcode: %s] [Questions: %d] [Answers: %d] [Authority: %d] [Additional: %d]",
		rcode, len(resp.Question), len(resp.Answer), len(resp.Ns), len(resp.Extra))

	if len(resp.Answer) > 0 {
		firstRR := resp.Answer[0].String()
		if len(firstRR) > 80 {
			firstRR = firstRR[:80] + "..."
		}
		result += fmt.Sprintf(" [FirstRR: %s]", firstRR)
	}

	return result
}

func grabUDPBanner(ip string, port int, timeout time.Duration) string {
	addr := net.JoinHostPort(ip, fmt.Sprint(port))

	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	probe := udpProbe(port)
	if _, err := conn.Write(probe); err != nil {
		return ""
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	data := buf[:n]
	return parseUDPBanner(port, data)
}

func udpProbe(port int) []byte {
	switch port {

	case 53: // DNS version.bind
		return []byte{
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x07, 0x76, 0x65, 0x72,
			0x73, 0x69, 0x6f, 0x6e, 0x04, 0x62, 0x69, 0x6e,
			0x64, 0x00, 0x00, 0x10, 0x00, 0x03,
		}

	case 123: // NTP
		return []byte{0x1b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	case 161: // SNMP sysDescr
		return []byte{
			0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
			0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
			0x04, 0x70, 0x65, 0x65, 0x72, 0x02, 0x01, 0x00,
			0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06,
			0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00,
		}

	case 5060: // SIP
		return []byte(
			"OPTIONS sip:test SIP/2.0\r\n" +
				"Via: SIP/2.0/UDP scanner\r\n" +
				"From: <sip:scan@scan>\r\n" +
				"To: <sip:test@test>\r\n" +
				"Call-ID: scan\r\n" +
				"CSeq: 1 OPTIONS\r\n" +
				"Content-Length: 0\r\n\r\n")

	default:
		return []byte{0x00}
	}
}

func parseUDPBanner(port int, data []byte) string {
	length := len(data)

	switch port {

	case 53:
		return fmt.Sprintf("[DNS] [Length: %d]", length)

	case 123:
		if length >= 48 {
			version := (data[0] >> 3) & 7
			stratum := data[1]
			return fmt.Sprintf("[NTP] [Version: %d] [Stratum: %d] [Length: %d]", version, stratum, length)
		}
		return fmt.Sprintf("[NTP] [Length: %d]", length)

	case 161:
		if bytes.Contains(data, []byte("public")) {
			return fmt.Sprintf("[SNMP] [Community: public] [Length: %d]", length)
		}
		return fmt.Sprintf("[SNMP] [Length: %d]", length)

	case 5060:
		if bytes.Contains(data, []byte("SIP/2.0")) {
			line := strings.SplitN(string(data), "\r\n", 2)[0]
			server := extractHeader(data, "Server")
			ua := extractHeader(data, "User-Agent")

			out := fmt.Sprintf("[SIP] [%s] [Length: %d]", line, length)
			if server != "" {
				out += fmt.Sprintf(" [Server: %s]", server)
			}
			if ua != "" {
				out += fmt.Sprintf(" [User-Agent: %s]", ua)
			}
			return out
		}
	}

	if isPrintable(data) {
		text := strings.TrimSpace(string(data))
		if len(text) > 80 {
			text = text[:80]
		}
		return fmt.Sprintf("[UDP] [Length: %d] [Data: %s]", length, text)
	}

	return fmt.Sprintf("[UDP] [Length: %d]", length)
}

func extractHeader(data []byte, name string) string {
	lines := strings.Split(string(data), "\r\n")
	prefix := strings.ToLower(name) + ":"

	for _, l := range lines {
		if strings.HasPrefix(strings.ToLower(l), prefix) {
			return strings.TrimSpace(l[len(prefix):])
		}
	}
	return ""
}

func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 9 || (c > 13 && c < 32) {
			return false
		}
	}
	return true
}
