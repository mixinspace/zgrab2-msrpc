package msrpc

import "regexp"

const (
	rpcVersionMajor = 5
	rpcVersionMinor = 0

	rpcPTYPERequest  = 0x00
	rpcPTYPEResponse = 0x02
	rpcPTYPEFault    = 0x03
	rpcPTYPEBind     = 0x0B
	rpcPTYPEBindAck  = 0x0C
	rpcPTYPEBindNak  = 0x0D

	rpcFlagFirstFrag = 0x01
	rpcFlagLastFrag  = 0x02
	rpcDataRepLE     = 0x10

	rpcAuthTypeNTLM  = 0x0A
	rpcAuthLevelConn = 0x02

	defaultMaxFragment   = 5840
	defaultMaxEPMEntries = 500
	maxEPMPages          = 8
)

const (
	rpcFaultNCAOpRangeError = 0x1C010002
	rpcFaultNCAUnknownIf    = 0x1C010003
	rpcFaultNCAProtoError   = 0x1C01000B
	rpcFaultAccessDenied    = 0x00000005
)

const (
	uuidEndpointMapper    = "E1AF8308-5D1F-11C9-91A4-08002B14A0FA"
	uuidIObjectExporter   = "99FCFEC4-5260-101B-BBCB-00AA0021347A"
	uuidNDRTransferSyntax = "8A885D04-1CEB-11C9-9FE8-08002B104860"
)

var (
	ipv4Regex = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Regex = regexp.MustCompile(`\b[0-9a-fA-F:]{2,}\b`)
)

type rpcPDU struct {
	Version uint8
	Minor   uint8
	Type    uint8
	Flags   uint8
	FragLen uint16
	AuthLen uint16
	CallID  uint32
	Body    []byte
	Raw     []byte
}

type towerFloor struct {
	LHS []byte
	RHS []byte
}

type parsedTower struct {
	Start         int
	End           int
	InterfaceUUID string
	VersionMajor  uint16
	VersionMinor  uint16
	Binding       string
}

// NTLMChallenge contains parsed NTLM challenge metadata when available.
type NTLMChallenge struct {
	TargetName      string   `json:"target_name,omitempty"`
	NetBIOSComputer string   `json:"netbios_computer,omitempty"`
	NetBIOSDomain   string   `json:"netbios_domain,omitempty"`
	DNSComputer     string   `json:"dns_computer,omitempty"`
	DNSDomain       string   `json:"dns_domain,omitempty"`
	DNSTree         string   `json:"dns_tree,omitempty"`
	TargetSPN       string   `json:"target_spn,omitempty"`
	SystemTime      string   `json:"system_time,omitempty"`
	BuildVersion    string   `json:"build_version,omitempty"`
	NTLMRevision    uint8    `json:"ntlm_revision,omitempty"`
	WindowsFamily   string   `json:"windows_family,omitempty"`
	CandidateCPEs   []string `json:"candidate_cpes,omitempty"`
}

// ResponsePDU describes the RPC PDU received during bind.
type ResponsePDU struct {
	Code uint8  `json:"code"`
	Name string `json:"name,omitempty"`
}

// SecondaryEndpoint describes the bind secondary address.
type SecondaryEndpoint struct {
	Raw  string `json:"raw,omitempty"`
	Port uint16 `json:"port,omitempty"`
}

// BindResult describes a bind/alter-context exchange.
type BindResult struct {
	Accepted           bool               `json:"accepted"`
	ResponsePDU        *ResponsePDU       `json:"response_pdu,omitempty"`
	AssociationGroupID uint32             `json:"association_group_id,omitempty"`
	SecondaryEndpoint  *SecondaryEndpoint `json:"secondary_endpoint,omitempty"`
	ContextResult      uint16             `json:"context_result,omitempty"`
	ContextReason      uint16             `json:"context_reason,omitempty"`
	NTLMChallenge      *NTLMChallenge     `json:"ntlm_challenge,omitempty"`
	Error              string             `json:"error,omitempty"`
}

// EPMInterface is a grouped Endpoint Mapper interface record.
type EPMInterface struct {
	InterfaceUUID string   `json:"interface_uuid,omitempty"`
	Version       string   `json:"version,omitempty"`
	Name          string   `json:"name,omitempty"`
	Protocol      string   `json:"protocol,omitempty"`
	Provider      string   `json:"provider,omitempty"`
	Bindings      []string `json:"bindings,omitempty"`
	ObjectUUIDs   []string `json:"object_uuids,omitempty"`
	Annotations   []string `json:"annotations,omitempty"`
}

// EPMUnresolved is an EPM record without a resolved interface UUID.
type EPMUnresolved struct {
	ObjectUUID string `json:"object_uuid,omitempty"`
	Binding    string `json:"binding,omitempty"`
	Annotation string `json:"annotation,omitempty"`
}

// EPMResult contains Endpoint Mapper lookup results.
type EPMResult struct {
	Success         bool            `json:"success"`
	InterfaceCount  int             `json:"interface_count,omitempty"`
	UnresolvedCount int             `json:"unresolved_count,omitempty"`
	Interfaces      []EPMInterface  `json:"interfaces,omitempty"`
	Unresolved      []EPMUnresolved `json:"unresolved,omitempty"`
	Error           string          `json:"error,omitempty"`
}

// IOXIDResult contains IObjectExporter::ServerAlive2 results.
type IOXIDResult struct {
	Success    bool     `json:"success"`
	COMVersion string   `json:"com_version,omitempty"`
	Bindings   []string `json:"bindings,omitempty"`
	IPv4       []string `json:"ipv4,omitempty"`
	IPv6       []string `json:"ipv6,omitempty"`
	Hostnames  []string `json:"hostnames,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// HTTPResult contains RPC-over-HTTP fingerprinting results.
type HTTPResult struct {
	Detected bool   `json:"detected"`
	Banner   string `json:"banner,omitempty"`
	Error    string `json:"error,omitempty"`
}

// ScanResults is the output of the scan.
type ScanResults struct {
	Mode  string       `json:"mode,omitempty"`
	Bind  *BindResult  `json:"bind,omitempty"`
	HTTP  *HTTPResult  `json:"http,omitempty"`
	IOXID *IOXIDResult `json:"ioxid,omitempty"`
	EPM   *EPMResult   `json:"epm,omitempty"`
}
