//package main
//
//import (
//	"fmt"
//	"log"
//
//	"github.com/google/gopacket"
//	"github.com/google/gopacket/layers"
//	"github.com/google/gopacket/pcap"
//)
//
//func main() {
//	devices, err := pcap.FindAllDevs()
//	if err != nil {
//		log.Fatal(err)
//	}
//	var device pcap.Interface
//	device = devices[3]
//
//	for _, d := range devices {
//		fmt.Println("Name:", d.Name)
//		fmt.Println("Description:", d.Description)
//		fmt.Println()
//	}
//
//	snapshotLen := int32(1600)
//	promiscuous := true
//	timeout := pcap.BlockForever
//
//	handle, err := pcap.OpenLive(device.Name, snapshotLen, promiscuous, timeout)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer handle.Close()
//
//	// Like tcpdump filter (optional)
//	err = handle.SetBPFFilter("tcp")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	fmt.Println("Listening on", device)
//
//	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
//
//	for packet := range packetSource.Packets() {
//
//		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
//			tcp := tcpLayer.(*layers.TCP)
//
//			fmt.Printf("TCP %s:%d -> %s:%d\n",
//				packet.NetworkLayer().NetworkFlow().Src(),
//				tcp.SrcPort,
//				packet.NetworkLayer().NetworkFlow().Dst(),
//				tcp.DstPort,
//			)
//		}
//	}
//}
// cmd/naabu/main.go  (enhanced fork)
// Drop-in replacement for the original main.go.
//
// New capabilities:
//   • Smart target parsing  — accepts ip:port, https://url, hostname, CIDR
//   • Per-port banner grab  — protocol-aware, TLS-capable
//   • Rich terminal display — coloured, structured, human-friendly
//   • Service detection     — SSH, HTTP, FTP, Redis, MongoDB, …
//   • Vulnerability scanner — local CVE signature DB, exposure checks
//   • Full scan map         — aggregated host/port/service/vuln table at end
// cmd/naabu/main.go  (enhanced fork)
// Drop-in replacement for the original main.go.
//
// New capabilities:
//   • Smart target parsing  — accepts ip:port, https://url, hostname, CIDR
//   • Per-port banner grab  — protocol-aware, TLS-capable
//   • Rich terminal display — coloured, structured, human-friendly
//   • Service detection     — SSH, HTTP, FTP, Redis, MongoDB, …
//   • Vulnerability scanner — local CVE signature DB, exposure checks
//   • Full scan map         — aggregated host/port/service/vuln table at end

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"naabu-dev/internal/pdcp"
	"naabu-dev/pkg/port"
	"naabu-dev/pkg/protocol"
	"naabu-dev/pkg/result"
	"naabu-dev/pkg/runner"
	"naabu-dev/pkg/target"
	"naabu-dev/pkg/vuln"

	"github.com/logrusorgru/aurora"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
)

func main() {
	// ── Parse options (same as upstream) ─────────────────────────────────────
	options := runner.ParseOptions()

	// ── Pre-process hosts: resolve url / ip:port formats ─────────────────────
	if len(options.Host) > 0 {
		targets, errs := target.ParseAll([]string(options.Host))
		for _, e := range errs {
			gologger.Warning().Msgf("Target parse warning: %s", e)
		}
		var cleanHosts []string
		for _, t := range targets {
			cleanHosts = append(cleanHosts, t.Host)
			// Inject port derived from URL scheme (e.g. https://host → port 443)
			if t.Port > 0 {
				gologger.Info().Msgf("Derived port %d from target %q", t.Port, t.Raw)
				if options.Ports != "" {
					options.Ports += fmt.Sprintf(",%d", t.Port)
				} else {
					options.Ports = fmt.Sprintf("%d", t.Port)
				}
			}
		}
		if len(cleanHosts) > 0 {
			options.Host = cleanHosts
		}
	}

	// ── Build scan map and wrap OnResult ─────────────────────────────────────
	// runner.NewScanMap, runner.EnhancedOnResult, runner.AllFindings are all
	// defined in pkg/runner/enhance.go — same package, no alias needed.
	scanMap := runner.NewScanMap()
	grabTimeout := 5 * time.Second
	originalOnResult := options.OnResult
	options.OnResult = runner.EnhancedOnResult(originalOnResult, options.NoColor, grabTimeout)

	// ── Local results file upload (unchanged from upstream) ───────────────────
	if options.AssetFileUpload != "" {
		_ = setupOptionalAssetUpload(options)
		file, err := os.Open(options.AssetFileUpload)
		if err != nil {
			gologger.Fatal().Msgf("Could not open file: %s\n", err)
		}
		defer file.Close()

		dec := json.NewDecoder(file)
		for dec.More() {
			var r runner.Result
			if err := dec.Decode(&r); err != nil {
				gologger.Fatal().Msgf("Could not decode jsonl file: %s\n", err)
			}
			service := &port.Service{
				DeviceType:  r.DeviceType,
				ExtraInfo:   r.ExtraInfo,
				HighVersion: r.HighVersion,
				Hostname:    r.Hostname,
				LowVersion:  r.LowVersion,
				Method:      r.Method,
				Name:        r.Name,
				OSType:      r.OSType,
				Product:     r.Product,
				Proto:       r.Proto,
				RPCNum:      r.RPCNum,
				ServiceFP:   r.ServiceFP,
				Tunnel:      r.Tunnel,
				Version:     r.Version,
				Confidence:  r.Confidence,
			}
			options.OnResult(&result.HostResult{
				Host: r.Host,
				IP:   r.IP,
				Ports: []*port.Port{{
					Port:     r.Port,
					Protocol: protocol.ParseProtocol(r.Protocol),
					TLS:      r.TLS,
					Service:  service,
				}},
			})
		}
		printFinalSummaries(scanMap, options.NoColor)
		options.OnClose()
		return
	}

	// ── Setup optional PDCP asset upload ─────────────────────────────────────
	_ = setupOptionalAssetUpload(options)

	// ── Create runner ─────────────────────────────────────────────────────────
	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	// ── Signal handling ───────────────────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-c
		gologger.Info().Msgf("Received signal: %s, exiting gracefully...\n", sig)
		cancel()

		if options.ResumeCfg != nil && options.ResumeCfg.ShouldSaveResume() {
			gologger.Info().Msgf("Creating resume file: %s\n", runner.DefaultResumeFilePath())
			if err := options.ResumeCfg.SaveResumeConfig(); err != nil {
				gologger.Error().Msgf("Couldn't create resume file: %s\n", err)
			}
		}

		printFinalSummaries(scanMap, options.NoColor)

		if naabuRunner != nil {
			naabuRunner.ShowScanResultOnExit()
			if err := naabuRunner.Close(); err != nil {
				gologger.Error().Msgf("Couldn't close runner: %s\n", err)
			}
		}
		os.Exit(1)
	}()

	// ── Run port enumeration ──────────────────────────────────────────────────
	if err := naabuRunner.RunEnumeration(ctx); err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}

	printFinalSummaries(scanMap, options.NoColor)

	defer func() {
		if err := naabuRunner.Close(); err != nil {
			gologger.Error().Msgf("Couldn't close runner: %s\n", err)
		}
		if options.ResumeCfg != nil {
			options.ResumeCfg.CleanupResumeConfig()
		}
	}()
}

// printFinalSummaries renders the scan map + vuln summary after enumeration.
func printFinalSummaries(scanMap *runner.ScanMap, noColor bool) {
	scanMap.PrintMap(noColor)
	findings := runner.AllFindings()
	vuln.PrintSummary(findings, noColor)
}

// setupOptionalAssetUpload is unchanged from upstream.
func setupOptionalAssetUpload(opts *runner.Options) *pdcp.UploadWriter {
	var mustEnable bool
	if opts.AssetUpload || opts.AssetID != "" || opts.AssetName != "" || pdcp.EnableCloudUpload {
		mustEnable = true
	}

	a := aurora.NewAurora(!opts.NoColor)
	if !mustEnable {
		if !pdcp.HideAutoSaveMsg {
			gologger.Print().Msgf("[%s] UI Dashboard is disabled, Use -dashboard option to enable",
				a.BrightYellow("WRN"))
		}
		return nil
	}

	gologger.Info().Msgf("To view results in UI dashboard, visit https://cloud.projectdiscovery.io/assets upon completion.")

	h := &pdcpauth.PDCPCredHandler{}
	creds, err := h.GetCreds()
	if err != nil {
		if err != pdcpauth.ErrNoCreds && !pdcp.HideAutoSaveMsg {
			gologger.Verbose().Msgf("Could not get credentials for cloud upload: %s\n", err)
		}
		pdcpauth.CheckNValidateCredentials("naabu")
		return nil
	}

	writer, err := pdcp.NewUploadWriterCallback(context.Background(), creds)
	if err != nil {
		gologger.Error().Msgf("failed to setup UI dashboard: %s", err)
		return nil
	}
	if writer == nil {
		gologger.Error().Msgf("something went wrong, could not setup UI dashboard")
		return nil
	}

	opts.OnResult = writer.GetWriterCallback()
	opts.OnClose = func() { writer.Close() }

	if opts.AssetID != "" {
		writer.SetAssetID(opts.AssetID)
	}
	if opts.AssetName != "" {
		writer.SetAssetGroupName(opts.AssetName)
	}
	if opts.TeamID != "" {
		writer.SetTeamID(opts.TeamID)
	}
	return writer
}
