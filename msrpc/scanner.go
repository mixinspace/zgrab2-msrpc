// Package msrpc contains the zgrab2 module implementation for MSRPC.
package msrpc

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

const (
	msrpcTCPPort  = 135
	msrpcHTTPPort = 593
)

// Flags are the command-line flags for the msrpc module.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`

	UseHTTP     bool   `long:"http" description:"Use RPC-over-HTTP mode (ncacn_http); port 135 is rewritten to 593 in this mode"`
	DoEPM       bool   `long:"epm" description:"Run Endpoint Mapper lookup (TCP and HTTP mode)"`
	DoIOXID     bool   `long:"ioxid" description:"Run IOXIDResolver ServerAlive2 (TCP and HTTP mode)"`
	UseNTLM     bool   `long:"ntlm" description:"Include NTLM negotiate auth in bind requests and parse challenge metadata"`
	EPMPolicy   string `long:"epm-policy" description:"EPM enrichment policy: all or verified" default:"all"`
	ReadTimeout int    `long:"read-timeout" description:"Read timeout in milliseconds" default:"3000"`
	MaxReadSize int    `long:"max-read-size" description:"Maximum amount of data to read in KiB (1024 bytes)" default:"1024"`
	MaxEntries  int    `long:"max-entries" description:"Maximum endpoint entries to request per EPM lookup page" default:"500"`
}

// Module implements the zgrab2.ScanModule interface.
type Module struct{}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

// RegisterModule registers the msrpc scan module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("msrpc", "MSRPC", module.Description(), msrpcTCPPort, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a default flags object.
func (m *Module) NewFlags() any {
	return new(Flags)
}

// NewScanner returns a new scanner.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (m *Module) Description() string {
	return "Probe Microsoft RPC over TCP (135) or HTTP (593), including Endpoint Mapper and IOXID metadata"
}

// Validate validates the flags.
func (f *Flags) Validate(_ []string) error {
	if f.ReadTimeout <= 0 || f.MaxReadSize <= 0 || f.MaxEntries <= 0 {
		return zgrab2.ErrInvalidArguments
	}
	f.EPMPolicy = strings.ToLower(strings.TrimSpace(f.EPMPolicy))
	if f.EPMPolicy == "" {
		f.EPMPolicy = epmPolicyAll
	}
	if f.EPMPolicy != epmPolicyAll && f.EPMPolicy != epmPolicyVerified {
		return zgrab2.ErrInvalidArguments
	}
	return nil
}

// Help returns this module's help string.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the scanner.
func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, ok := flags.(*Flags)
	if !ok {
		return zgrab2.ErrMismatchedFlags
	}
	if f.MaxEntries > defaultMaxEPMEntries {
		f.MaxEntries = defaultMaxEPMEntries
	}
	if f.UseHTTP && f.Port == msrpcTCPPort {
		f.Port = msrpcHTTPPort
	}
	s.config = f
	return nil
}

// InitPerSender initializes scanner state for a sender.
func (s *Scanner) InitPerSender(_ int) error {
	return nil
}

// GetName returns the scanner name.
func (s *Scanner) GetName() string {
	return s.config.Name
}

// GetTrigger returns the trigger.
func (s *Scanner) GetTrigger() string {
	return s.config.Trigger
}

// Protocol returns the protocol identifier.
func (s *Scanner) Protocol() string {
	if s.config.UseHTTP {
		return "msrpc-http"
	}
	return "msrpc"
}

// Scan connects to a host and performs the configured scan.
func (s *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	if s.config.UseHTTP {
		return s.scanHTTP(target)
	}
	return s.scanTCP(target)
}

func (s *Scanner) scanTCP(target zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	results := &ScanResults{Mode: "tcp"}

	if !s.config.UseNTLM && !s.config.DoEPM && !s.config.DoIOXID {
		probeConn, probeErr := target.Open(&s.config.BaseFlags)
		if probeErr != nil {
			return zgrab2.TryGetScanStatus(probeErr), nil, probeErr
		}
		bind, _, bindErr := s.performBind(probeConn, uuidEndpointMapper, 3, 0, 1, nil)
		_ = probeConn.Close()
		if bind != nil {
			results.Bind = bind
		}
		if bindErr != nil {
			return zgrab2.TryGetScanStatus(bindErr), results, bindErr
		}
		if bind == nil || !bind.Accepted {
			return zgrab2.SCAN_PROTOCOL_ERROR, results, fmt.Errorf("epm bind probe failed")
		}
		return zgrab2.SCAN_SUCCESS, results, nil
	}

	if s.config.UseNTLM {
		ntlmToken, _ := buildNTLMNegotiateToken()
		ntlmConn, ntlmOpenErr := target.Open(&s.config.BaseFlags)
		if ntlmOpenErr != nil {
			return zgrab2.TryGetScanStatus(ntlmOpenErr), nil, ntlmOpenErr
		}
		ntlmBind, _, ntlmErr := s.performBind(ntlmConn, uuidEndpointMapper, 3, 0, 1, ntlmToken)
		_ = ntlmConn.Close()
		if ntlmBind != nil {
			results.Bind = ntlmBind
		}
		if ntlmErr != nil {
			return zgrab2.TryGetScanStatus(ntlmErr), results, ntlmErr
		}
		if ntlmBind == nil || !ntlmBind.Accepted {
			return zgrab2.SCAN_PROTOCOL_ERROR, results, fmt.Errorf("ntlm bind failed")
		}
	}

	if s.config.DoEPM {
		epmConn, epmOpenErr := target.Open(&s.config.BaseFlags)
		if epmOpenErr != nil {
			return zgrab2.TryGetScanStatus(epmOpenErr), results, epmOpenErr
		}
		epm, epmBind, epmErr := s.performEPMLookupConn(epmConn, target)
		_ = epmConn.Close()
		if results.Bind == nil && epmBind != nil {
			results.Bind = epmBind
		}
		if epmErr != nil {
			return zgrab2.TryGetScanStatus(epmErr), results, epmErr
		}
		results.EPM = epm
	}

	if s.config.DoIOXID {
		ioxidConn, ioxidOpenErr := target.Open(&s.config.BaseFlags)
		if ioxidOpenErr != nil {
			return zgrab2.TryGetScanStatus(ioxidOpenErr), results, ioxidOpenErr
		}

		ioxid, ioxidBind, ioxidErr := s.performIOXIDLookupConn(ioxidConn)
		_ = ioxidConn.Close()
		if results.Bind == nil && ioxidBind != nil {
			results.Bind = ioxidBind
		}
		if ioxidErr != nil {
			ioxid.Error = ioxidErr.Error()
		}
		results.IOXID = ioxid
	}

	return zgrab2.SCAN_SUCCESS, results, nil
}

func (s *Scanner) scanHTTP(target zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	results := &ScanResults{
		Mode: "http",
		HTTP: &HTTPResult{},
	}

	verifyHTTPBanner := func(conn net.Conn) (bool, error) {
		banner, detected, bannerErr := s.readNCACNHTTPBanner(conn)
		if banner != "" {
			results.HTTP.Banner = banner
		}
		if detected {
			results.HTTP.Detected = true
		}
		if bannerErr != nil {
			if bannerErr != io.EOF {
				results.HTTP.Error = bannerErr.Error()
			}
			return false, bannerErr
		}
		return detected, nil
	}

	if !s.config.UseNTLM && !s.config.DoEPM && !s.config.DoIOXID {
		probeConn, probeErr := target.Open(&s.config.BaseFlags)
		if probeErr != nil {
			return zgrab2.TryGetScanStatus(probeErr), nil, probeErr
		}
		detected, bannerErr := verifyHTTPBanner(probeConn)
		_ = probeConn.Close()
		if bannerErr != nil {
			return zgrab2.TryGetScanStatus(bannerErr), results, bannerErr
		}
		if !detected {
			return zgrab2.SCAN_PROTOCOL_ERROR, results, fmt.Errorf("ncacn_http banner not detected")
		}
		return zgrab2.SCAN_SUCCESS, results, nil
	}

	if s.config.UseNTLM {
		ntlmConn, ntlmOpenErr := target.Open(&s.config.BaseFlags)
		if ntlmOpenErr != nil {
			return zgrab2.TryGetScanStatus(ntlmOpenErr), results, ntlmOpenErr
		}
		detected, bannerErr := verifyHTTPBanner(ntlmConn)
		if bannerErr != nil {
			_ = ntlmConn.Close()
			return zgrab2.TryGetScanStatus(bannerErr), results, bannerErr
		}
		if !detected {
			_ = ntlmConn.Close()
			return zgrab2.SCAN_PROTOCOL_ERROR, results, fmt.Errorf("ncacn_http banner not detected")
		}

		ntlmToken, _ := buildNTLMNegotiateToken()
		bind, _, bindErr := s.performBind(ntlmConn, uuidEndpointMapper, 3, 0, 1, ntlmToken)
		_ = ntlmConn.Close()
		if bind != nil {
			results.Bind = bind
		}
		if bindErr != nil {
			return zgrab2.TryGetScanStatus(bindErr), results, bindErr
		}
		if bind == nil || !bind.Accepted {
			return zgrab2.SCAN_PROTOCOL_ERROR, results, fmt.Errorf("ntlm bind failed over http")
		}
	}

	if s.config.DoEPM {
		epmConn, epmOpenErr := target.Open(&s.config.BaseFlags)
		if epmOpenErr != nil {
			return zgrab2.TryGetScanStatus(epmOpenErr), results, epmOpenErr
		}
		detected, bannerErr := verifyHTTPBanner(epmConn)
		if bannerErr != nil {
			_ = epmConn.Close()
			return zgrab2.TryGetScanStatus(bannerErr), results, bannerErr
		}
		if !detected {
			_ = epmConn.Close()
			return zgrab2.SCAN_PROTOCOL_ERROR, results, fmt.Errorf("ncacn_http banner not detected")
		}

		epm, epmBind, epmErr := s.performEPMLookupConn(epmConn, target)
		_ = epmConn.Close()
		if results.Bind == nil && epmBind != nil {
			results.Bind = epmBind
		}
		if epmErr != nil {
			return zgrab2.TryGetScanStatus(epmErr), results, epmErr
		}
		results.EPM = epm
	}

	if s.config.DoIOXID {
		ioxidConn, ioxidOpenErr := target.Open(&s.config.BaseFlags)
		if ioxidOpenErr != nil {
			return zgrab2.TryGetScanStatus(ioxidOpenErr), results, ioxidOpenErr
		}
		detected, bannerErr := verifyHTTPBanner(ioxidConn)
		if bannerErr != nil {
			_ = ioxidConn.Close()
			return zgrab2.TryGetScanStatus(bannerErr), results, bannerErr
		}
		if !detected {
			_ = ioxidConn.Close()
			return zgrab2.SCAN_PROTOCOL_ERROR, results, fmt.Errorf("ncacn_http banner not detected")
		}

		ioxid, ioxidBind, ioxidErr := s.performIOXIDLookupConn(ioxidConn)
		_ = ioxidConn.Close()
		if results.Bind == nil && ioxidBind != nil {
			results.Bind = ioxidBind
		}
		if ioxidErr != nil {
			ioxid.Error = ioxidErr.Error()
		}
		results.IOXID = ioxid
	}

	return zgrab2.SCAN_SUCCESS, results, nil
}

func (s *Scanner) readNCACNHTTPBanner(conn net.Conn) (string, bool, error) {
	timeout := time.Duration(s.config.ReadTimeout) * time.Millisecond
	conn.SetReadDeadline(time.Now().Add(timeout))
	peek := make([]byte, 256)
	n, err := conn.Read(peek)
	if err != nil {
		return "", false, err
	}
	if n <= 0 {
		return "", false, nil
	}
	banner := strings.TrimSpace(string(peek[:n]))
	if strings.Contains(strings.ToLower(banner), "ncacn_http/1.0") {
		return banner, true, nil
	}
	return banner, false, nil
}
