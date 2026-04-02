package msrpc

import (
	"sort"
	"strings"
)

const (
	roleUnknown                    = "unknown"
	roleDomainController           = "domain_controller"
	roleMemberServer               = "member_server"
	roleFileServer                 = "file_server"
	rolePrintServer                = "print_server"
	roleRDSTerminalServer          = "rds_terminal_server"
	roleManagementServer           = "management_server"
	roleCOMDCOMApplicationServer   = "com_dcom_application_server"
	roleRPCOverHTTPPublishedServer = "rpc_over_http_published_server"
	roleInfrastructureServer       = "infrastructure_server"
	roleStandaloneSpecializedHost  = "standalone_or_specialized_host"
)

var inferredRoles = []string{
	roleDomainController,
	roleMemberServer,
	roleFileServer,
	rolePrintServer,
	roleRDSTerminalServer,
	roleManagementServer,
	roleCOMDCOMApplicationServer,
	roleRPCOverHTTPPublishedServer,
	roleInfrastructureServer,
	roleStandaloneSpecializedHost,
}

// RoleCandidate represents one scored role variant.
type RoleCandidate struct {
	Role  string `json:"role,omitempty"`
	Score int    `json:"score,omitempty"`
}

// ServerRole contains the inferred role and supporting score data.
type ServerRole struct {
	Role          string          `json:"role,omitempty"`
	Confidence    string          `json:"confidence,omitempty"`
	Score         int             `json:"score,omitempty"`
	RunnerUp      string          `json:"runner_up,omitempty"`
	RunnerUpScore int             `json:"runner_up_score,omitempty"`
	Signals       []string        `json:"signals,omitempty"`
	Candidates    []RoleCandidate `json:"candidates,omitempty"`
}

type roleAccumulator struct {
	score   int
	signals []string
	seen    map[string]struct{}
}

type roleContext struct {
	mode              string
	httpDetected      bool
	httpBanner        string
	epmSuccess        bool
	ioxidSuccess      bool
	domainLike        bool
	serverFamily      bool
	bindings          []string
	fields            []string
	surfaceCount      int
	bindingCount      int
	transportCount    int
	ncalrpcCount      int
	ioxidBindingCount int
	httpBindingCount  int
	pipeBindingCount  int
	multiHomed        bool
}

func finalizeResults(results *ScanResults, includeRole bool) *ScanResults {
	if results == nil {
		return nil
	}
	if !includeRole {
		results.ServerRole = nil
		return results
	}
	results.ServerRole = inferServerRole(results)
	return results
}

func inferServerRole(results *ScanResults) *ServerRole {
	ctx := buildRoleContext(results)
	accumulators := make(map[string]*roleAccumulator, len(inferredRoles))
	for _, role := range inferredRoles {
		accumulators[role] = &roleAccumulator{seen: make(map[string]struct{})}
	}

	addScore := func(role string, points int, signal string) {
		if points <= 0 {
			return
		}
		acc := accumulators[role]
		acc.score += points
		if signal == "" {
			return
		}
		if _, exists := acc.seen[signal]; exists {
			return
		}
		acc.seen[signal] = struct{}{}
		acc.signals = append(acc.signals, signal)
	}

	hasSvcctl := containsAny(ctx.bindings, `\pipe\svcctl`) || containsAny(ctx.fields, "svcctl", "service control manager")
	hasWinreg := containsAny(ctx.bindings, `\pipe\winreg`) || containsAny(ctx.fields, "winreg", "remote registry")
	hasSamr := containsAny(ctx.bindings, `\pipe\samr`) || containsAny(ctx.fields, "samr")
	hasLsarpc := containsAny(ctx.bindings, `\pipe\lsarpc`) || containsAny(ctx.fields, "lsarpc")
	hasNetlogon := containsAny(ctx.bindings, `\pipe\netlogon`) || containsAny(ctx.fields, "netlogon")
	hasSpoolss := containsAny(ctx.bindings, `\pipe\spoolss`) || containsAny(ctx.fields, "spoolss", "winspool", "iremotewinspool", "spoolsv.exe")
	hasSrvsvc := containsAny(ctx.bindings, `\pipe\srvsvc`) || containsAny(ctx.fields, "srvsvc")
	hasWkssvc := containsAny(ctx.bindings, `\pipe\wkssvc`) || containsAny(ctx.fields, "wkssvc")
	hasAtsvc := containsAny(ctx.bindings, `\pipe\atsvc`) || containsAny(ctx.fields, "atsvc")
	hasEventlog := containsAny(ctx.bindings, `\pipe\eventlog`) || containsAny(ctx.fields, "eventlog")
	hasDrsuapi := containsAny(ctx.fields, "drsuapi", "ms-drsr")
	hasNTDS := containsAny(ctx.bindings, "ncalrpc:[ntds_lpc]") || containsAny(ctx.fields, "ntds_lpc", "ntdsai.dll")
	hasFRS2 := containsAny(ctx.fields, "frstransport", "ms-frs2", "frs2 service")
	hasDnsServer := containsAny(ctx.fields, "dnsserver", "ms-dnsp")
	hasICPR := containsAny(ctx.fields, "icertpassage", "ms-icpr")

	hasTermSrv := containsAny(ctx.fields, "termsrv")
	hasSessEnv := containsAny(ctx.fields, "sessenv")
	hasHydra := containsAny(ctx.fields, "hydra") || containsAny(ctx.bindings, `\pipe\hydralspipe`)
	hasTSSD := containsAny(ctx.fields, "tssd")
	hasTerminalServices := containsAny(ctx.fields, "terminal services", "terminal server")
	hasTsProxy := containsAny(ctx.fields, "tsproxy", "tsproxyrpcinterface", "tsproxymgmt")
	hasTScPub := containsAny(ctx.fields, "tscpubrpc", "tssessiondirectoryqueryapi")
	hasRDSGatewayProto := containsAny(ctx.fields, "ms-tsgu")
	hasRDSSessionProto := containsAny(ctx.fields, "ms-tsts")

	hasWMsgKRpc := containsAny(ctx.fields, "wmsgkrpc")
	hasDCOMProtocol := containsAny(ctx.fields, "ms-dcom", "dcom", "iobjectexporter", "iremunknown")
	hasOLEMarker := hasToken(ctx.fields, "ole") || containsAny(ctx.fields, "combase.dll", "rpcss.dll")

	adminSurfaceCount := countTrue(hasSvcctl, hasWinreg, hasEventlog, hasAtsvc, hasSrvsvc)
	roleMarkerCount := countTrue(hasSvcctl, hasWinreg, hasSamr, hasLsarpc, hasNetlogon, hasSpoolss, hasSrvsvc, hasWkssvc, hasAtsvc, hasEventlog)
	rdsSignalCount := countTrue(hasTermSrv, hasSessEnv, hasHydra, hasTSSD, hasTerminalServices, hasTsProxy, hasTScPub, hasRDSGatewayProto, hasRDSSessionProto)
	comSignalCount := countTrue(hasWMsgKRpc, hasDCOMProtocol, hasOLEMarker)
	hasSurfaceData := ctx.surfaceCount > 0 || ctx.bindingCount > 0

	if hasNetlogon {
		addScore(roleDomainController, 6, "visible netlogon RPC surface")
	}
	if ctx.domainLike {
		addScore(roleDomainController, 2, "NTLM naming looks domain-joined")
	}
	if hasLsarpc {
		addScore(roleDomainController, 1, "visible LSA RPC surface")
	}
	if hasSamr {
		addScore(roleDomainController, 1, "visible SAMR surface")
	}
	if hasNetlogon && ctx.domainLike {
		addScore(roleDomainController, 3, "netlogon aligns with domain-style NTLM metadata")
	}
	if hasNetlogon && (hasLsarpc || hasSamr) {
		addScore(roleDomainController, 2, "netlogon is paired with identity/security RPC")
	}
	if containsAny(ctx.fields, "dsroler") {
		addScore(roleDomainController, 2, "Directory Services role RPC is visible")
	}
	if hasDrsuapi {
		addScore(roleDomainController, 5, "drsuapi directory replication RPC is visible")
	}
	if hasNTDS {
		addScore(roleDomainController, 4, "NTDS local endpoint is registered")
	}
	if hasFRS2 {
		addScore(roleDomainController, 2, "directory replication transport RPC is visible")
	}
	if hasDnsServer {
		addScore(roleDomainController, 2, "DNS server management RPC is visible")
	}
	if hasICPR {
		addScore(roleDomainController, 1, "certificate enrollment RPC is visible")
	}
	if hasDrsuapi && hasNTDS {
		addScore(roleDomainController, 4, "directory replication aligns with NTDS local state")
	}
	if hasNetlogon && hasDrsuapi {
		addScore(roleDomainController, 2, "netlogon and AD replication are both exposed")
	}
	if hasNetlogon && hasDnsServer {
		addScore(roleDomainController, 1, "netlogon appears alongside DNS server management")
	}
	if countTrue(hasNetlogon, hasLsarpc, hasSamr, hasDrsuapi, hasNTDS) >= 4 {
		addScore(roleDomainController, 3, "multiple core Active Directory control-plane RPC surfaces agree")
	}

	if ctx.domainLike {
		addScore(roleMemberServer, 4, "NTLM naming looks domain-joined")
	}
	if hasSvcctl {
		addScore(roleMemberServer, 1, "service control RPC is exposed")
	}
	if hasSrvsvc {
		addScore(roleMemberServer, 1, "server service RPC is exposed")
	}
	if hasEventlog {
		addScore(roleMemberServer, 1, "event log RPC is exposed")
	}
	if hasWinreg {
		addScore(roleMemberServer, 1, "remote registry RPC is exposed")
	}
	if adminSurfaceCount >= 3 {
		addScore(roleMemberServer, 2, "multiple administrative RPC surfaces are exposed")
	}
	if ctx.domainLike && adminSurfaceCount >= 2 && !hasNetlogon {
		addScore(roleMemberServer, 3, "domain-like host exposes admin RPC without a strong DC marker")
	}
	if ctx.serverFamily {
		addScore(roleMemberServer, 1, "NTLM version metadata looks like Windows Server")
	}

	if hasSrvsvc {
		addScore(roleFileServer, 5, "srvsvc is exposed")
	}
	if hasWkssvc {
		addScore(roleFileServer, 2, "wkssvc is exposed")
	}
	if ctx.pipeBindingCount >= 2 {
		addScore(roleFileServer, 1, "multiple named-pipe bindings are visible")
	}
	if hasSrvsvc && hasWkssvc {
		addScore(roleFileServer, 2, "srvsvc and wkssvc appear together")
	}
	if ctx.domainLike && hasSrvsvc {
		addScore(roleFileServer, 1, "domain-like host exposes SMB server management")
	}

	if hasSpoolss {
		addScore(rolePrintServer, 8, "spooler RPC surface is exposed")
	}
	if hasSpoolss && hasSrvsvc {
		addScore(rolePrintServer, 2, "print and server-service RPC appear together")
	}

	if hasTermSrv {
		addScore(roleRDSTerminalServer, 4, "TermSrv markers are present")
	}
	if hasSessEnv {
		addScore(roleRDSTerminalServer, 3, "SessEnv markers are present")
	}
	if hasHydra {
		addScore(roleRDSTerminalServer, 3, "Hydra markers are present")
	}
	if hasTSSD {
		addScore(roleRDSTerminalServer, 3, "TSSD markers are present")
	}
	if hasTerminalServices {
		addScore(roleRDSTerminalServer, 3, "Terminal Services / Terminal Server markers are present")
	}
	if hasTsProxy {
		addScore(roleRDSTerminalServer, 4, "TSProxy markers are present")
	}
	if hasTScPub {
		addScore(roleRDSTerminalServer, 3, "Terminal Services session publication markers are present")
	}
	if hasRDSGatewayProto {
		addScore(roleRDSTerminalServer, 3, "MS-TSGU protocol is visible")
	}
	if hasRDSSessionProto {
		addScore(roleRDSTerminalServer, 2, "MS-TSTS protocol is visible")
	}
	if hasHydra && hasRDSSessionProto {
		addScore(roleRDSTerminalServer, 2, "Hydra licensing aligns with Terminal Services runtime RPC")
	}
	if rdsSignalCount >= 2 {
		addScore(roleRDSTerminalServer, 2, "multiple RDS-related components are visible")
	}
	if rdsSignalCount >= 4 {
		addScore(roleRDSTerminalServer, 3, "several independent RDS signals agree")
	}
	if hasTsProxy && ctx.httpBindingCount > 0 {
		addScore(roleRDSTerminalServer, 3, "TSProxy is published over RPC-over-HTTP")
	}
	if hasTsProxy && ctx.httpDetected {
		addScore(roleRDSTerminalServer, 2, "host responded to ncacn_http and exposes TSProxy")
	}

	if hasSvcctl {
		addScore(roleManagementServer, 3, "service control RPC is exposed")
	}
	if hasWinreg {
		addScore(roleManagementServer, 3, "remote registry RPC is exposed")
	}
	if hasEventlog {
		addScore(roleManagementServer, 2, "event log RPC is exposed")
	}
	if hasAtsvc {
		addScore(roleManagementServer, 2, "scheduler RPC is exposed")
	}
	if adminSurfaceCount >= 3 {
		addScore(roleManagementServer, 3, "broad administrative RPC surface is exposed")
	}
	if hasSvcctl && hasWinreg && hasEventlog {
		addScore(roleManagementServer, 2, "service, registry, and event management are all visible")
	}

	if hasDCOMProtocol {
		addScore(roleCOMDCOMApplicationServer, 2, "DCOM-related interfaces are visible")
	}
	if hasOLEMarker {
		addScore(roleCOMDCOMApplicationServer, 3, "OLE/DCOM markers are present")
	}
	if hasWMsgKRpc {
		addScore(roleCOMDCOMApplicationServer, 3, "WMsgKRpc markers are present")
	}
	if ctx.ncalrpcCount >= 3 {
		addScore(roleCOMDCOMApplicationServer, 3, "several ncalrpc endpoints are registered")
	}
	if ctx.ioxidSuccess {
		addScore(roleCOMDCOMApplicationServer, 2, "IOXID ServerAlive2 completed successfully")
	}
	if ctx.ioxidBindingCount >= 3 && ctx.ioxidSuccess {
		addScore(roleCOMDCOMApplicationServer, 2, "IOXID returned several bindings")
	}
	if comSignalCount >= 2 {
		addScore(roleCOMDCOMApplicationServer, 2, "multiple COM/DCOM indicators agree")
	}

	if ctx.mode == "http" && (ctx.httpDetected || ctx.httpBindingCount > 0 || ctx.epmSuccess) {
		addScore(roleRPCOverHTTPPublishedServer, 2, "scan is running over a confirmed RPC-over-HTTP path")
	}
	if ctx.httpDetected {
		addScore(roleRPCOverHTTPPublishedServer, 3, "ncacn_http banner was detected")
	}
	if strings.Contains(ctx.httpBanner, "ncacn_http/1.0") {
		addScore(roleRPCOverHTTPPublishedServer, 1, "banner confirms ncacn_http/1.0")
	}
	if ctx.epmSuccess {
		addScore(roleRPCOverHTTPPublishedServer, 2, "EPM lookup succeeded on the same endpoint")
	}
	if ctx.httpBindingCount > 0 {
		addScore(roleRPCOverHTTPPublishedServer, 4, "EPM/IOXID returned ncacn_http bindings")
	}
	if ctx.httpBindingCount > 1 {
		addScore(roleRPCOverHTTPPublishedServer, 1, "multiple RPC-over-HTTP bindings are published")
	}

	if ctx.surfaceCount >= 10 {
		addScore(roleInfrastructureServer, 4, "many RPC interfaces are exposed")
	}
	if ctx.bindingCount >= 12 {
		addScore(roleInfrastructureServer, 3, "many unique bindings are registered")
	}
	if ctx.transportCount >= 3 {
		addScore(roleInfrastructureServer, 3, "multiple RPC transports are in use")
	}
	if roleMarkerCount >= 5 {
		addScore(roleInfrastructureServer, 3, "several independent RPC management surfaces are visible")
	}
	if ctx.multiHomed {
		addScore(roleInfrastructureServer, 2, "IOXID reveals multiple hostnames or addresses")
	}
	if ctx.serverFamily {
		addScore(roleInfrastructureServer, 1, "NTLM version metadata looks like Windows Server")
	}

	if hasSurfaceData && !ctx.domainLike {
		addScore(roleStandaloneSpecializedHost, 3, "surface is visible without domain-style NTLM naming")
	}
	if hasSurfaceData && ctx.surfaceCount > 0 && ctx.surfaceCount <= 2 {
		addScore(roleStandaloneSpecializedHost, 3, "very small RPC surface is visible")
	}
	if hasSurfaceData && ctx.bindingCount > 0 && ctx.bindingCount <= 3 {
		addScore(roleStandaloneSpecializedHost, 1, "only a few RPC bindings were discovered")
	}
	if hasSurfaceData && roleMarkerCount <= 1 {
		addScore(roleStandaloneSpecializedHost, 2, "there are few role-specific RPC markers")
	}
	if hasSurfaceData && !hasNetlogon {
		addScore(roleStandaloneSpecializedHost, 1, "no netlogon marker was found")
	}

	type scoredRole struct {
		role    string
		score   int
		signals []string
	}

	scored := make([]scoredRole, 0, len(inferredRoles))
	for _, role := range inferredRoles {
		acc := accumulators[role]
		scored = append(scored, scoredRole{
			role:    role,
			score:   acc.score,
			signals: acc.signals,
		})
	}

	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return scored[i].score > scored[j].score
		}
		return scored[i].role < scored[j].role
	})

	top := scored[0]
	second := scored[1]
	if top.score <= 0 {
		return &ServerRole{
			Role:       roleUnknown,
			Confidence: "low",
			Signals:    []string{"insufficient role-specific MSRPC signals"},
		}
	}

	confidence := classifyConfidence(top.role, top.score, second.score)
	out := &ServerRole{
		Role:       top.role,
		Confidence: confidence,
		Score:      top.score,
		Signals:    trimSignals(top.signals, 8),
	}
	if second.score > 0 {
		out.RunnerUp = second.role
		out.RunnerUpScore = second.score
	}

	for _, item := range scored {
		if item.score <= 0 || len(out.Candidates) >= 3 {
			continue
		}
		out.Candidates = append(out.Candidates, RoleCandidate{
			Role:  item.role,
			Score: item.score,
		})
	}

	return out
}

func buildRoleContext(results *ScanResults) roleContext {
	ctx := roleContext{}
	if results == nil {
		return ctx
	}

	ctx.mode = strings.ToLower(strings.TrimSpace(results.Mode))
	if results.HTTP != nil {
		ctx.httpDetected = results.HTTP.Detected
		ctx.httpBanner = strings.ToLower(strings.TrimSpace(results.HTTP.Banner))
	}
	if results.EPM != nil {
		ctx.epmSuccess = results.EPM.Success
		ctx.surfaceCount = results.EPM.InterfaceCount + results.EPM.UnresolvedCount
	}
	if results.IOXID != nil {
		ctx.ioxidSuccess = results.IOXID.Success
		ctx.ioxidBindingCount = len(results.IOXID.Bindings)
	}

	bindingSet := make(map[string]struct{})
	fieldSet := make(map[string]struct{})
	transports := make(map[string]struct{})

	addBinding := func(raw string) {
		value := normalizeRoleValue(raw)
		if value == "" {
			return
		}
		if _, exists := bindingSet[value]; exists {
			return
		}
		bindingSet[value] = struct{}{}
		ctx.bindings = append(ctx.bindings, value)

		switch {
		case strings.HasPrefix(value, "ncalrpc:"):
			ctx.ncalrpcCount++
			transports["ncalrpc"] = struct{}{}
		case strings.HasPrefix(value, "ncacn_http:"):
			ctx.httpBindingCount++
			transports["ncacn_http"] = struct{}{}
		case strings.HasPrefix(value, "ncacn_np:"):
			ctx.pipeBindingCount++
			transports["ncacn_np"] = struct{}{}
		case strings.HasPrefix(value, "ncacn_ip_tcp:"):
			transports["ncacn_ip_tcp"] = struct{}{}
		case strings.HasPrefix(value, "ncadg_ip_udp:"):
			transports["ncadg_ip_udp"] = struct{}{}
		case strings.HasPrefix(value, "netbios:"):
			transports["netbios"] = struct{}{}
		case strings.HasPrefix(value, "ip:"):
			transports["ip"] = struct{}{}
		}
	}

	addField := func(raw string) {
		value := normalizeRoleValue(raw)
		if value == "" {
			return
		}
		if _, exists := fieldSet[value]; exists {
			return
		}
		fieldSet[value] = struct{}{}
		ctx.fields = append(ctx.fields, value)
	}

	if results.EPM != nil {
		for _, iface := range results.EPM.Interfaces {
			addField(iface.Name)
			addField(iface.Protocol)
			addField(iface.Provider)
			for _, binding := range iface.Bindings {
				addBinding(binding)
			}
			for _, annotation := range iface.Annotations {
				addField(annotation)
			}
		}
		for _, unresolved := range results.EPM.Unresolved {
			addBinding(unresolved.Binding)
			addField(unresolved.Annotation)
		}
	}

	if results.IOXID != nil {
		for _, binding := range results.IOXID.Bindings {
			addBinding(binding)
		}
	}

	ctx.bindingCount = len(ctx.bindings)
	ctx.transportCount = len(transports)
	if results.IOXID != nil {
		ctx.multiHomed = len(results.IOXID.IPv4) > 1 || len(results.IOXID.IPv6) > 1 || len(results.IOXID.Hostnames) > 1
	}
	if ctx.surfaceCount == 0 {
		ctx.surfaceCount = ctx.bindingCount
	}

	if results.Bind != nil && results.Bind.NTLMChallenge != nil {
		ntlm := results.Bind.NTLMChallenge
		ctx.domainLike = isDomainLike(ntlm)
		ctx.serverFamily = isWindowsServerFamily(ntlm)
		addField(ntlm.TargetName)
		addField(ntlm.NetBIOSComputer)
		addField(ntlm.NetBIOSDomain)
		addField(ntlm.DNSComputer)
		addField(ntlm.DNSDomain)
		addField(ntlm.DNSTree)
		addField(ntlm.TargetSPN)
		addField(ntlm.WindowsFamily)
		for _, cpe := range ntlm.CandidateCPEs {
			addField(cpe)
		}
	}

	sort.Strings(ctx.bindings)
	sort.Strings(ctx.fields)
	return ctx
}

func isDomainLike(ch *NTLMChallenge) bool {
	if ch == nil {
		return false
	}
	if ch.DNSComputer != "" && ch.DNSDomain != "" {
		return true
	}
	if ch.DNSComputer != "" && ch.DNSTree != "" {
		return true
	}
	if ch.NetBIOSComputer != "" && ch.NetBIOSDomain != "" && !strings.EqualFold(ch.NetBIOSComputer, ch.NetBIOSDomain) {
		return true
	}
	return false
}

func isWindowsServerFamily(ch *NTLMChallenge) bool {
	if ch == nil {
		return false
	}
	if strings.Contains(strings.ToLower(ch.WindowsFamily), "server") {
		return true
	}
	for _, cpe := range ch.CandidateCPEs {
		if strings.Contains(strings.ToLower(cpe), "windows_server") {
			return true
		}
	}
	return false
}

func normalizeRoleValue(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func containsAny(values []string, needles ...string) bool {
	for _, value := range values {
		for _, needle := range needles {
			if strings.Contains(value, needle) {
				return true
			}
		}
	}
	return false
}

func hasToken(values []string, token string) bool {
	for _, value := range values {
		if containsToken(value, token) {
			return true
		}
	}
	return false
}

func containsToken(value, token string) bool {
	start := 0
	for {
		idx := strings.Index(value[start:], token)
		if idx < 0 {
			return false
		}
		idx += start
		beforeOK := idx == 0 || !isAlphaNum(value[idx-1])
		afterPos := idx + len(token)
		afterOK := afterPos >= len(value) || !isAlphaNum(value[afterPos])
		if beforeOK && afterOK {
			return true
		}
		start = idx + len(token)
	}
}

func isAlphaNum(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
}

func countTrue(values ...bool) int {
	total := 0
	for _, value := range values {
		if value {
			total++
		}
	}
	return total
}

func classifyConfidence(role string, topScore, secondScore int) string {
	margin := topScore - secondScore
	confidence := "low"
	switch {
	case topScore >= 8 && margin >= 4:
		confidence = "high"
	case topScore >= 5 && margin >= 2:
		confidence = "medium"
	}

	switch role {
	case roleInfrastructureServer, roleMemberServer, roleRPCOverHTTPPublishedServer, roleStandaloneSpecializedHost:
		if confidence == "high" {
			return "medium"
		}
	}

	return confidence
}

func trimSignals(signals []string, max int) []string {
	if len(signals) <= max {
		return signals
	}
	return signals[:max]
}
