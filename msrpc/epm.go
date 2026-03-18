package msrpc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/zmap/zgrab2"
)

// performEPMLookupConn executes a full Endpoint Mapper step on an existing connection:
// bind to EPM interface first, then run paged ept_lookup requests.
func (s *Scanner) performEPMLookupConn(conn net.Conn, target zgrab2.ScanTarget) (*EPMResult, *BindResult, error) {
	ret := &EPMResult{Endpoints: make([]EPMEndpoint, 0)}

	bind, _, bindErr := s.performBind(conn, uuidEndpointMapper, 3, 0, 1, nil)
	if bindErr != nil {
		return ret, bind, bindErr
	}
	if bind == nil || !bind.Accepted {
		return ret, bind, fmt.Errorf("endpoint mapper bind failed")
	}

	epm, epmErr := s.performEPMLookup(conn, target)
	if epmErr != nil {
		epm.Error = epmErr.Error()
	}
	return epm, bind, nil
}

// performEPMLookup issues ept_lookup (opnum 2) requests and walks the entry_handle
// cursor until the server returns a zero handle or page limit is reached.
func (s *Scanner) performEPMLookup(conn net.Conn, target zgrab2.ScanTarget) (*EPMResult, error) {
	ret := &EPMResult{Endpoints: make([]EPMEndpoint, 0)}
	callID := uint32(2)
	var entryHandle [20]byte
	hadResponse := false

	for page := 0; page < maxEPMPages; page++ {
		stub := buildEptLookupStub(entryHandle, uint32(s.config.MaxEntries))
		req := buildRequestPDU(callID, 0, 2, stub)
		callID++
		pdu, err := s.sendAndRecvRPC(conn, req)
		if err != nil {
			return ret, err
		}
		if pdu.Type == rpcPTYPEFault {
			if status, ok := parseRPCFaultStatus(pdu.Body); ok {
				return ret, fmt.Errorf("epm request returned fault: %s (0x%08x)", rpcFaultStatusName(status), status)
			}
			return ret, fmt.Errorf("epm request returned fault")
		}
		if pdu.Type != rpcPTYPEResponse {
			return ret, fmt.Errorf("unexpected EPM response packet type: %d", pdu.Type)
		}
		hadResponse = true

		respStub, err := parseResponseStub(pdu.Body)
		if err != nil {
			return ret, err
		}
		if len(respStub) < 4+20 {
			break
		}
		parsedEndpoints, nextHandle, parseErr := parseEPMEntries(respStub, target.Host())
		if parseErr != nil {
			// Best-effort extraction if strict NDR parsing fails.
			copy(entryHandle[:], respStub[4:24])
			// Fallback to lightweight tower/annotation extraction when NDR parsing fails.
			towers := parseTowers(respStub, target.Host())
			annotations := extractAnnotations(respStub)
			for i := range towers {
				ep := EPMEndpoint{
					UUID:    towers[i].InterfaceUUID,
					Version: fmt.Sprintf("v%d.%d", towers[i].VersionMajor, towers[i].VersionMinor),
					Binding: towers[i].Binding,
				}
				if i < len(annotations) {
					ep.Annotation = sanitizeAnnotation([]byte(annotations[i]))
				}
				ret.Endpoints = append(ret.Endpoints, ep)
			}
		} else {
			entryHandle = nextHandle
			ret.Endpoints = append(ret.Endpoints, parsedEndpoints...)
		}

		if isZeroEntryHandle(entryHandle) {
			break
		}
	}

	ret.Endpoints = normalizeEPMEndpoints(ret.Endpoints)
	ret.Success = hadResponse
	ret.EndpointCount = len(ret.Endpoints)
	return ret, nil
}

// parseEPMEntries decodes the NDR body returned by ept_lookup.
// Structure (simplified):
//   - max_count + next_entry_handle
//   - entries array with object UUID / annotation / tower reference
//   - concatenated tower blobs
func parseEPMEntries(stub []byte, fallbackHost string) ([]EPMEndpoint, [20]byte, error) {
	type entry struct {
		objectUUID string
		annotation string
		towerRef   uint32
	}

	var nextHandle [20]byte
	if len(stub) < 4+20+4+8 {
		return nil, nextHandle, fmt.Errorf("short epm stub")
	}
	idx := 0
	maxCount := int(binary.LittleEndian.Uint32(stub[idx : idx+4]))
	idx += 4
	copy(nextHandle[:], stub[idx:idx+20])
	idx += 20
	numEnts := int(binary.LittleEndian.Uint32(stub[idx : idx+4]))
	idx += 4
	_ = binary.LittleEndian.Uint32(stub[idx : idx+4]) // offset
	idx += 4
	actualCount := int(binary.LittleEndian.Uint32(stub[idx : idx+4]))
	idx += 4
	if actualCount < 0 || actualCount > 10000 {
		return nil, nextHandle, fmt.Errorf("invalid epm actual_count: %d", actualCount)
	}
	if maxCount > 0 && actualCount > maxCount {
		actualCount = maxCount
	}
	if numEnts > 0 && actualCount > numEnts {
		actualCount = numEnts
	}

	entries := make([]entry, 0, actualCount)
	for i := 0; i < actualCount; i++ {
		if idx+28 > len(stub) {
			return nil, nextHandle, fmt.Errorf("short epm entry at index %d", i)
		}
		obj := rpcBytesToUUIDString(stub[idx : idx+16])
		idx += 16
		towerRef := binary.LittleEndian.Uint32(stub[idx : idx+4])
		idx += 4
		_ = binary.LittleEndian.Uint32(stub[idx : idx+4]) // ann offset
		idx += 4
		annCount := int(binary.LittleEndian.Uint32(stub[idx : idx+4]))
		idx += 4
		if annCount < 0 || idx+annCount > len(stub) {
			return nil, nextHandle, fmt.Errorf("invalid annotation length at index %d", i)
		}
		annotation := sanitizeAnnotation(stub[idx : idx+annCount])
		idx += annCount
		idx = align4(idx)
		entries = append(entries, entry{
			objectUUID: obj,
			annotation: annotation,
			towerRef:   towerRef,
		})
	}

	endpoints := make([]EPMEndpoint, 0, actualCount)
	for i := range entries {
		ep := EPMEndpoint{
			UUID:       entries[i].objectUUID,
			Annotation: entries[i].annotation,
		}
		if entries[i].towerRef != 0 {
			if idx+8 > len(stub) {
				break
			}
			maxCount := int(binary.LittleEndian.Uint32(stub[idx : idx+4]))
			idx += 4
			towerLen := int(binary.LittleEndian.Uint32(stub[idx : idx+4]))
			idx += 4
			if towerLen < 0 {
				break
			}
			dataLen := towerLen
			if dataLen > maxCount && maxCount > 0 {
				dataLen = maxCount
			}
			if dataLen < 0 || idx+dataLen > len(stub) {
				break
			}
			towerData := stub[idx : idx+dataLen]
			idx += dataLen
			idx = align4(idx)

			towerUUID, maj, min, binding, ok := parseTowerData(towerData, fallbackHost)
			if ok {
				if towerUUID != "" {
					ep.UUID = towerUUID
				}
				ep.Version = fmt.Sprintf("v%d.%d", maj, min)
				ep.Binding = binding
			}
		}
		if ep.UUID != "" || ep.Binding != "" || ep.Annotation != "" {
			endpoints = append(endpoints, ep)
		}
	}
	return endpoints, nextHandle, nil
}

// parseTowerData decodes one RPC tower and extracts:
// interface UUID/version from floor 0 + transport binding from remaining floors.
func parseTowerData(data []byte, fallbackHost string) (string, uint16, uint16, string, bool) {
	if len(data) < 2 {
		return "", 0, 0, "", false
	}
	floorCount := int(binary.LittleEndian.Uint16(data[:2]))
	if floorCount < 3 || floorCount > 10 {
		return "", 0, 0, "", false
	}
	pos := 2
	floors := make([]towerFloor, 0, floorCount)
	for i := 0; i < floorCount; i++ {
		if pos+2 > len(data) {
			return "", 0, 0, "", false
		}
		lhsLen := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
		pos += 2
		if lhsLen <= 0 || pos+lhsLen > len(data) {
			return "", 0, 0, "", false
		}
		lhs := data[pos : pos+lhsLen]
		pos += lhsLen
		if pos+2 > len(data) {
			return "", 0, 0, "", false
		}
		rhsLen := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
		pos += 2
		if rhsLen < 0 || pos+rhsLen > len(data) {
			return "", 0, 0, "", false
		}
		rhs := data[pos : pos+rhsLen]
		pos += rhsLen
		floors = append(floors, towerFloor{LHS: lhs, RHS: rhs})
	}
	if len(floors) < 3 || len(floors[0].LHS) != 19 || len(floors[0].RHS) < 2 {
		return "", 0, 0, "", false
	}
	if floors[0].LHS[0] != 0x0D {
		return "", 0, 0, "", false
	}
	uuid := rpcBytesToUUIDString(floors[0].LHS[1:17])
	maj := binary.LittleEndian.Uint16(floors[0].LHS[17:19])
	min := binary.LittleEndian.Uint16(floors[0].RHS[:2])
	binding := floorsToBinding(floors[3:], fallbackHost)
	return uuid, maj, min, binding, true
}

// sanitizeAnnotation filters noisy/non-printable annotations to keep usable labels.
func sanitizeAnnotation(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	s := strings.TrimRight(string(raw), "\x00")
	s = strings.TrimSpace(s)
	if !looksLikeAnnotation(s) {
		return ""
	}
	return s
}

// align4 returns v aligned up to the next 4-byte boundary (NDR alignment rule).
func align4(v int) int {
	return (v + 3) &^ 3
}

// parseTowers is a best-effort scanner over raw ept_lookup stubs.
// It is used when strict NDR decoding fails but useful tower data is still present.
func parseTowers(blob []byte, fallbackHost string) []parsedTower {
	results := make([]parsedTower, 0)
	for i := 0; i+4 < len(blob); i++ {
		floorCount := int(binary.LittleEndian.Uint16(blob[i : i+2]))
		if floorCount < 3 || floorCount > 10 {
			continue
		}
		pos := i + 2
		floors := make([]towerFloor, 0, floorCount)
		valid := true
		for f := 0; f < floorCount; f++ {
			if pos+2 > len(blob) {
				valid = false
				break
			}
			lhsLen := int(binary.LittleEndian.Uint16(blob[pos : pos+2]))
			pos += 2
			if lhsLen <= 0 || lhsLen > 512 || pos+lhsLen > len(blob) {
				valid = false
				break
			}
			lhs := blob[pos : pos+lhsLen]
			pos += lhsLen
			if pos+2 > len(blob) {
				valid = false
				break
			}
			rhsLen := int(binary.LittleEndian.Uint16(blob[pos : pos+2]))
			pos += 2
			if rhsLen < 0 || rhsLen > 2048 || pos+rhsLen > len(blob) {
				valid = false
				break
			}
			rhs := blob[pos : pos+rhsLen]
			pos += rhsLen
			floors = append(floors, towerFloor{LHS: lhs, RHS: rhs})
		}
		if !valid || len(floors) < 3 {
			continue
		}
		if len(floors[0].LHS) != 19 || floors[0].LHS[0] != 0x0D {
			continue
		}
		if len(floors[1].LHS) != 19 || floors[1].LHS[0] != 0x0D {
			continue
		}
		if len(floors[0].RHS) < 2 {
			continue
		}
		uuid := rpcBytesToUUIDString(floors[0].LHS[1:17])
		maj := binary.LittleEndian.Uint16(floors[0].LHS[17:19])
		min := binary.LittleEndian.Uint16(floors[0].RHS[0:2])
		binding := floorsToBinding(floors[3:], fallbackHost)
		if uuid == "" {
			continue
		}
		results = append(results, parsedTower{
			Start:         i,
			End:           pos,
			InterfaceUUID: uuid,
			VersionMajor:  maj,
			VersionMinor:  min,
			Binding:       binding,
		})
		i = pos - 1
	}
	return results
}

// floorsToBinding translates transport/address tower floors into canonical binding strings.
// Examples: ncacn_ip_tcp:host[port], ncacn_np:host[\pipe\name], ncalrpc:[endpoint].
func floorsToBinding(floors []towerFloor, fallbackHost string) string {
	template := ""
	for _, floor := range floors {
		if len(floor.LHS) != 1 {
			continue
		}
		id := floor.LHS[0]
		switch id {
		case 0x07:
			if len(floor.RHS) >= 2 {
				port := binary.BigEndian.Uint16(floor.RHS[:2])
				template = fmt.Sprintf("ncacn_ip_tcp:%%s[%d]", port)
			}
		case 0x08:
			if len(floor.RHS) >= 2 {
				port := binary.BigEndian.Uint16(floor.RHS[:2])
				template = fmt.Sprintf("ncadg_ip_udp:%%s[%d]", port)
			}
		case 0x09:
			if len(floor.RHS) == 4 {
				ip := net.IP(floor.RHS).String()
				if template != "" {
					return fmt.Sprintf(template, ip)
				}
				return "IP: " + ip
			}
		case 0x0F:
			pipe := trimNullASCII(floor.RHS)
			template = fmt.Sprintf("ncacn_np:%%s[%s]", pipe)
		case 0x10:
			name := trimNullASCII(floor.RHS)
			return fmt.Sprintf("ncalrpc:[%s]", name)
		case 0x01, 0x11:
			host := trimNullASCII(floor.RHS)
			if template != "" {
				return fmt.Sprintf(template, host)
			}
			return "NetBIOS: " + host
		case 0x1F:
			if len(floor.RHS) >= 2 {
				port := binary.BigEndian.Uint16(floor.RHS[:2])
				template = fmt.Sprintf("ncacn_http:%%s[%d]", port)
			}
		}
	}
	if template != "" {
		host := fallbackHost
		if host == "" {
			host = "0.0.0.0"
		}
		return fmt.Sprintf(template, host)
	}
	return ""
}

// extractAnnotations scans printable ASCII segments and keeps plausible annotation candidates.
func extractAnnotations(blob []byte) []string {
	found := make(map[string]bool)
	out := make([]string, 0)
	for i := 0; i < len(blob); i++ {
		if !isASCIIPrint(blob[i]) {
			continue
		}
		j := i
		for j < len(blob) && isASCIIPrint(blob[j]) {
			j++
		}
		if j-i < 4 {
			i = j
			continue
		}
		s := strings.TrimSpace(string(blob[i:j]))
		if looksLikeAnnotation(s) && !found[s] {
			found[s] = true
			out = append(out, s)
		}
		i = j
	}
	sort.Strings(out)
	return out
}

// looksLikeAnnotation applies heuristics to reduce false positives from raw byte scanning.
func looksLikeAnnotation(s string) bool {
	if s == "" {
		return false
	}
	l := strings.ToLower(s)
	if strings.Contains(l, "ncacn_") || strings.Contains(l, "\\pipe\\") {
		return false
	}
	if strings.Count(s, " ") > 3 {
		return false
	}
	if !hasAllowedAnnotationChars(s) {
		return false
	}
	if len(s) <= 4 {
		if !isLetterOnly(s) {
			return false
		}
		if !isAllLowerOrUpper(s) {
			return false
		}
	}
	if len(s) <= 6 && hasDigit(s) && !strings.HasPrefix(s, "LRPC-") && !strings.HasPrefix(s, "OLE") {
		return false
	}
	hasLetter := false
	for _, ch := range s {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			hasLetter = true
			break
		}
	}
	return hasLetter
}

// hasAllowedAnnotationChars restricts strings to a conservative printable set.
func hasAllowedAnnotationChars(s string) bool {
	for _, ch := range s {
		if (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == ' ' || ch == '-' || ch == '_' || ch == '.' || ch == '\\' || ch == ':' {
			continue
		}
		return false
	}
	return true
}

// isLetterOnly returns true if s contains only ASCII letters.
func isLetterOnly(s string) bool {
	for _, ch := range s {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			continue
		}
		return false
	}
	return true
}

// isAllLowerOrUpper returns true if all letters in s share one case.
func isAllLowerOrUpper(s string) bool {
	hasLower := false
	hasUpper := false
	for _, ch := range s {
		if ch >= 'a' && ch <= 'z' {
			hasLower = true
			continue
		}
		if ch >= 'A' && ch <= 'Z' {
			hasUpper = true
		}
	}
	return !hasLower || !hasUpper
}

// hasDigit returns true if s contains any ASCII digit.
func hasDigit(s string) bool {
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			return true
		}
	}
	return false
}

// normalizeEPMEndpoints deduplicates and merges endpoint variants produced by strict/fallback paths.
func normalizeEPMEndpoints(input []EPMEndpoint) []EPMEndpoint {
	type keyed struct {
		key string
		ep  EPMEndpoint
	}

	out := make([]keyed, 0, len(input))
	indexByKey := make(map[string]int, len(input))
	for _, ep := range input {
		ep.UUID = strings.ToLower(strings.TrimSpace(ep.UUID))
		ep.Version = strings.TrimSpace(ep.Version)
		ep.Binding = strings.TrimSpace(ep.Binding)
		ep.Annotation = sanitizeAnnotation([]byte(ep.Annotation))
		if ep.UUID == "" && ep.Binding == "" && ep.Annotation == "" {
			continue
		}

		key := ep.UUID + "|" + ep.Binding
		if key == "|" {
			key = ep.UUID + "|" + ep.Annotation
		}
		idx, found := indexByKey[key]
		if !found {
			indexByKey[key] = len(out)
			out = append(out, keyed{key: key, ep: ep})
			continue
		}

		current := out[idx].ep
		if current.Version == "" && ep.Version != "" {
			current.Version = ep.Version
		}
		if annotationScore(ep.Annotation) > annotationScore(current.Annotation) {
			current.Annotation = ep.Annotation
		}
		if current.UUID == "" && ep.UUID != "" {
			current.UUID = ep.UUID
		}
		if current.Binding == "" && ep.Binding != "" {
			current.Binding = ep.Binding
		}
		out[idx].ep = current
	}

	normalized := make([]EPMEndpoint, 0, len(out))
	for _, item := range out {
		normalized = append(normalized, item.ep)
	}
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].UUID != normalized[j].UUID {
			return normalized[i].UUID < normalized[j].UUID
		}
		if normalized[i].Binding != normalized[j].Binding {
			return normalized[i].Binding < normalized[j].Binding
		}
		return normalized[i].Annotation < normalized[j].Annotation
	})
	return normalized
}

// annotationScore picks the most informative annotation among duplicates.
func annotationScore(s string) int {
	if s == "" {
		return 0
	}
	score := len(s)
	switch {
	case strings.HasPrefix(s, "LRPC-"):
		score += 20
	case strings.HasPrefix(s, "OLE"):
		score += 15
	case strings.HasPrefix(s, "WMsgKRpc"):
		score += 15
	case strings.HasPrefix(s, "SPPCTransportEndpoint-"):
		score += 15
	}
	if hasDigit(s) && !strings.HasPrefix(s, "LRPC-") && !strings.HasPrefix(s, "OLE") && !strings.HasPrefix(s, "WMsgKRpc") {
		score -= 8
	}
	return score
}

// isASCIIPrint checks if a byte is printable ASCII.
func isASCIIPrint(b byte) bool {
	return b >= 0x20 && b <= 0x7e
}

// trimNullASCII removes trailing NUL bytes from ASCII-like floor payloads.
func trimNullASCII(raw []byte) string {
	trimmed := bytes.TrimRight(raw, "\x00")
	return string(trimmed)
}

// isZeroEntryHandle returns true when EPM cursor handle indicates "end of enumeration".
func isZeroEntryHandle(h [20]byte) bool {
	for _, b := range h {
		if b != 0 {
			return false
		}
	}
	return true
}
