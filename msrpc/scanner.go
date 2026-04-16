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
	msrpcTCPPort = 135
)

// Flags are the command-line flags for the msrpc module.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`

	UseHTTP     bool   `long:"http" description:"Use RPC-over-HTTP mode (ncacn_http) on the selected port"`
	DoEPM       bool   `long:"epm" description:"Run Endpoint Mapper lookup (TCP and HTTP mode)"`
	DoIOXID     bool   `long:"ioxid" description:"Run IOXIDResolver ServerAlive2 (TCP and HTTP mode)"`
	UseNTLM     bool   `long:"ntlm" description:"Include NTLM negotiate auth in bind requests and parse challenge metadata"`
	IncludeRole bool   `long:"server-role" description:"Infer likely server role and include the server_role_heuristic field in the JSON output"`
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

func attachBindResult(results *ScanResults, bind *BindResult, setPrimary bool) {
	if results == nil || bind == nil {
		return
	}
	if setPrimary || results.Bind == nil {
		results.Bind = bind
	}
	if bind.NTLMChallenge != nil {
		results.NTLMChallenge = bind.NTLMChallenge
	}
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
	return "Probe Microsoft RPC over the selected port in TCP or HTTP mode, including Endpoint Mapper and IOXID metadata"
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
	finish := func(status zgrab2.ScanStatus, err error) (zgrab2.ScanStatus, any, error) {
		return status, finalizeResults(results, s.config.IncludeRole), err
	}

	if !s.config.UseNTLM && !s.config.DoEPM && !s.config.DoIOXID {
		probeConn, probeErr := target.Open(&s.config.BaseFlags)
		if probeErr != nil {
			return zgrab2.TryGetScanStatus(probeErr), nil, probeErr
		}
		bind, _, bindErr := s.performBind(probeConn, uuidEndpointMapper, 3, 0, 1, nil)
		_ = probeConn.Close()
		attachBindResult(results, bind, true)
		if bindErr != nil {
			return finish(zgrab2.TryGetScanStatus(bindErr), bindErr)
		}
		if bind == nil || !bind.Accepted {
			return finish(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("epm bind probe failed"))
		}
		return finish(zgrab2.SCAN_SUCCESS, nil)
	}

	if s.config.UseNTLM {
		ntlmToken, _ := buildNTLMNegotiateToken()
		ntlmConn, ntlmOpenErr := target.Open(&s.config.BaseFlags)
		if ntlmOpenErr != nil {
			return zgrab2.TryGetScanStatus(ntlmOpenErr), nil, ntlmOpenErr
		}
		ntlmBind, _, ntlmErr := s.performBind(ntlmConn, uuidEndpointMapper, 3, 0, 1, ntlmToken)
		_ = ntlmConn.Close()
		attachBindResult(results, ntlmBind, true)
		if ntlmErr != nil {
			return finish(zgrab2.TryGetScanStatus(ntlmErr), ntlmErr)
		}
		if ntlmBind == nil || !ntlmBind.Accepted {
			return finish(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("ntlm bind failed"))
		}
	}

	if s.config.DoEPM {
		epmConn, epmOpenErr := target.Open(&s.config.BaseFlags)
		if epmOpenErr != nil {
			return finish(zgrab2.TryGetScanStatus(epmOpenErr), epmOpenErr)
		}
		epm, epmBind, epmErr := s.performEPMLookupConn(epmConn, target)
		_ = epmConn.Close()
		attachBindResult(results, epmBind, false)
		if epmErr != nil {
			return finish(zgrab2.TryGetScanStatus(epmErr), epmErr)
		}
		results.EPM = epm
	}

	if s.config.DoIOXID {
		ioxidConn, ioxidOpenErr := target.Open(&s.config.BaseFlags)
		if ioxidOpenErr != nil {
			return finish(zgrab2.TryGetScanStatus(ioxidOpenErr), ioxidOpenErr)
		}

		ioxid, ioxidBind, ioxidErr := s.performIOXIDLookupConn(ioxidConn)
		_ = ioxidConn.Close()
		attachBindResult(results, ioxidBind, false)
		if ioxidErr != nil {
			ioxid.Error = ioxidErr.Error()
		}
		results.IOXID = ioxid
	}

	return finish(zgrab2.SCAN_SUCCESS, nil)
}

func (s *Scanner) scanHTTP(target zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	results := &ScanResults{
		Mode: "http",
		HTTP: &HTTPResult{},
	}
	finish := func(status zgrab2.ScanStatus, err error) (zgrab2.ScanStatus, any, error) {
		return status, finalizeResults(results, s.config.IncludeRole), err
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
			return finish(zgrab2.TryGetScanStatus(bannerErr), bannerErr)
		}
		if !detected {
			return finish(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("ncacn_http banner not detected"))
		}
		return finish(zgrab2.SCAN_SUCCESS, nil)
	}

	if s.config.UseNTLM {
		ntlmConn, ntlmOpenErr := target.Open(&s.config.BaseFlags)
		if ntlmOpenErr != nil {
			return finish(zgrab2.TryGetScanStatus(ntlmOpenErr), ntlmOpenErr)
		}
		detected, bannerErr := verifyHTTPBanner(ntlmConn)
		if bannerErr != nil {
			_ = ntlmConn.Close()
			return finish(zgrab2.TryGetScanStatus(bannerErr), bannerErr)
		}
		if !detected {
			_ = ntlmConn.Close()
			return finish(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("ncacn_http banner not detected"))
		}

		ntlmToken, _ := buildNTLMNegotiateToken()
		bind, _, bindErr := s.performBind(ntlmConn, uuidEndpointMapper, 3, 0, 1, ntlmToken)
		_ = ntlmConn.Close()
		attachBindResult(results, bind, true)
		if bindErr != nil {
			return finish(zgrab2.TryGetScanStatus(bindErr), bindErr)
		}
		if bind == nil || !bind.Accepted {
			return finish(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("ntlm bind failed over http"))
		}
	}

	if s.config.DoEPM {
		epmConn, epmOpenErr := target.Open(&s.config.BaseFlags)
		if epmOpenErr != nil {
			return finish(zgrab2.TryGetScanStatus(epmOpenErr), epmOpenErr)
		}
		detected, bannerErr := verifyHTTPBanner(epmConn)
		if bannerErr != nil {
			_ = epmConn.Close()
			return finish(zgrab2.TryGetScanStatus(bannerErr), bannerErr)
		}
		if !detected {
			_ = epmConn.Close()
			return finish(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("ncacn_http banner not detected"))
		}

		epm, epmBind, epmErr := s.performEPMLookupConn(epmConn, target)
		_ = epmConn.Close()
		attachBindResult(results, epmBind, false)
		if epmErr != nil {
			return finish(zgrab2.TryGetScanStatus(epmErr), epmErr)
		}
		results.EPM = epm
	}

	if s.config.DoIOXID {
		ioxidConn, ioxidOpenErr := target.Open(&s.config.BaseFlags)
		if ioxidOpenErr != nil {
			return finish(zgrab2.TryGetScanStatus(ioxidOpenErr), ioxidOpenErr)
		}
		detected, bannerErr := verifyHTTPBanner(ioxidConn)
		if bannerErr != nil {
			_ = ioxidConn.Close()
			return finish(zgrab2.TryGetScanStatus(bannerErr), bannerErr)
		}
		if !detected {
			_ = ioxidConn.Close()
			return finish(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("ncacn_http banner not detected"))
		}

		ioxid, ioxidBind, ioxidErr := s.performIOXIDLookupConn(ioxidConn)
		_ = ioxidConn.Close()
		attachBindResult(results, ioxidBind, false)
		if ioxidErr != nil {
			ioxid.Error = ioxidErr.Error()
		}
		results.IOXID = ioxid
	}

	return finish(zgrab2.SCAN_SUCCESS, nil)
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
