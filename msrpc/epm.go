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

const (
	ndrUint16Size = 2
	ndrUint32Size = 4
)

const (
	epmEntryHandleSize     = 20
	epmStubMinForHandle    = ndrUint32Size + epmEntryHandleSize
	epmLookupHeaderMinSize = ndrUint32Size + epmEntryHandleSize + ndrUint32Size + 8
	epmEntryFixedSize      = 28
	epmMaxActualCount      = 10000

	towerMinFloorCount    = 3
	towerMaxFloorCount    = 10
	towerInterfaceLHSLen  = 19
	towerInterfaceProtoID = 0x0D
	towerScanMaxLHSLen    = 512
	towerScanMaxRHSLen    = 2048

	towerIfaceUUIDFrom    = 1
	towerIfaceUUIDTo      = 17
	towerIfaceMajorFrom   = 17
	towerIfaceMajorTo     = 19
	towerIfaceMinorFrom   = 0
	towerIfaceMinorTo     = 2
	towerBindingFromFloor = 3
)

const (
	towerIDIPTCP  byte = 0x07
	towerIDIPUDP  byte = 0x08
	towerIDIPv4   byte = 0x09
	towerIDNP     byte = 0x0F
	towerIDLRPC   byte = 0x10
	towerIDNBName byte = 0x01
	towerIDNBHost byte = 0x11
	towerIDHTTP   byte = 0x1F
)

type epmEntryRecord struct {
	objectUUID string
	annotation string
	towerRef   uint32
}

type ndrCursor struct {
	buf []byte
	idx int
}

func newNDRCursor(buf []byte, start int) *ndrCursor {
	return &ndrCursor{buf: buf, idx: start}
}

func (c *ndrCursor) Pos() int {
	return c.idx
}

func (c *ndrCursor) Has(n int) bool {
	if n < 0 {
		return false
	}
	return c.idx+n <= len(c.buf)
}

func (c *ndrCursor) ReadBytes(n int) ([]byte, bool) {
	if !c.Has(n) {
		return nil, false
	}
	raw := c.buf[c.idx : c.idx+n]
	c.idx += n
	return raw, true
}

func (c *ndrCursor) ReadUint16() (uint16, bool) {
	raw, ok := c.ReadBytes(ndrUint16Size)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint16(raw), true
}

func (c *ndrCursor) ReadUint32() (uint32, bool) {
	raw, ok := c.ReadBytes(ndrUint32Size)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint32(raw), true
}

func (c *ndrCursor) Align4() {
	c.idx = align4(c.idx)
}

// performEPMLookupConn executes a full Endpoint Mapper step on an existing connection:
// bind to EPM interface first, then run paged ept_lookup requests.
func (s *Scanner) performEPMLookupConn(conn net.Conn, target zgrab2.ScanTarget) (*EPMResult, *BindResult, error) {
	result := &EPMResult{Endpoints: make([]EPMEndpoint, 0)}

	bind, _, bindErr := s.performBind(conn, uuidEndpointMapper, 3, 0, 1, nil)
	if bindErr != nil {
		return result, bind, bindErr
	}

	if bind == nil || !bind.Accepted {
		return result, bind, fmt.Errorf("endpoint mapper bind failed")
	}

	epmResult, epmErr := s.performEPMLookup(conn, target)
	if epmErr != nil {
		epmResult.Error = epmErr.Error()
	}

	return epmResult, bind, nil
}

// performEPMLookup issues ept_lookup (opnum 2) requests and walks the entry_handle
// cursor until the server returns a zero handle or page limit is reached.
func (s *Scanner) performEPMLookup(conn net.Conn, target zgrab2.ScanTarget) (*EPMResult, error) {
	result := &EPMResult{Endpoints: make([]EPMEndpoint, 0)}
	callID := uint32(2)
	var entryHandle [epmEntryHandleSize]byte
	hadResponse := false
	fallbackHost := target.Host()

	for page := 0; page < maxEPMPages; page++ {
		requestStub := buildEptLookupStub(entryHandle, uint32(s.config.MaxEntries))
		requestPDU := buildRequestPDU(callID, 0, 2, requestStub)
		callID++

		pdu, err := s.sendAndRecvRPC(conn, requestPDU)
		if err != nil {
			return result, err
		}

		if err := validateEPMLookupResponsePDU(pdu); err != nil {
			return result, err
		}
		hadResponse = true

		responseStub, err := parseResponseStub(pdu.Body)
		if err != nil {
			return result, err
		}

		if len(responseStub) < epmStubMinForHandle {
			break
		}

		endpoints, nextHandle, parseErr := parseEPMEntries(responseStub, fallbackHost)
		if parseErr != nil {
			// Best-effort extraction if strict NDR parsing fails.
			updateEntryHandleFromStub(responseStub, &entryHandle)
			result.Endpoints = append(result.Endpoints, buildFallbackEndpoints(responseStub, fallbackHost)...)
		} else {
			entryHandle = nextHandle
			result.Endpoints = append(result.Endpoints, endpoints...)
		}

		if isZeroEntryHandle(entryHandle) {
			break
		}
	}

	result.Endpoints = normalizeEPMEndpoints(result.Endpoints)
	result.Success = hadResponse
	result.EndpointCount = len(result.Endpoints)
	return result, nil
}

func validateEPMLookupResponsePDU(pdu *rpcPDU) error {
	if pdu.Type == rpcPTYPEFault {
		if status, ok := parseRPCFaultStatus(pdu.Body); ok {
			return fmt.Errorf("epm request returned fault: %s (0x%08x)", rpcFaultStatusName(status), status)
		}
		return fmt.Errorf("epm request returned fault")
	}
	if pdu.Type != rpcPTYPEResponse {
		return fmt.Errorf("unexpected EPM response packet type: %d", pdu.Type)
	}
	return nil
}

func updateEntryHandleFromStub(stub []byte, entryHandle *[epmEntryHandleSize]byte) {
	cursor := newNDRCursor(stub, 0)
	_, _ = cursor.ReadUint32() // max_count
	handleBytes, ok := cursor.ReadBytes(epmEntryHandleSize)
	if ok {
		copy(entryHandle[:], handleBytes)
	}
}

func buildFallbackEndpoints(stub []byte, fallbackHost string) []EPMEndpoint {
	towers := parseTowers(stub, fallbackHost)
	annotations := extractAnnotations(stub)

	endpoints := make([]EPMEndpoint, 0, len(towers))
	for i := range towers {
		ep := EPMEndpoint{
			UUID:    towers[i].InterfaceUUID,
			Version: fmt.Sprintf("v%d.%d", towers[i].VersionMajor, towers[i].VersionMinor),
			Binding: towers[i].Binding,
		}
		if i < len(annotations) {
			ep.Annotation = sanitizeAnnotation([]byte(annotations[i]))
		}
		endpoints = append(endpoints, ep)
	}
	return endpoints
}

// parseEPMEntries decodes the NDR body returned by ept_lookup.
// Structure (simplified):
//   - max_count + next_entry_handle
//   - entries array with object UUID / annotation / tower reference
//   - concatenated tower blobs
func parseEPMEntries(stub []byte, fallbackHost string) ([]EPMEndpoint, [epmEntryHandleSize]byte, error) {
	var nextHandle [epmEntryHandleSize]byte
	cursor := newNDRCursor(stub, 0)

	actualCount, err := parseEPMHeader(cursor, &nextHandle)
	if err != nil {
		return nil, nextHandle, err
	}

	entries, err := parseEPMEntryRecords(cursor, actualCount)
	if err != nil {
		return nil, nextHandle, err
	}

	endpoints := parseEPMEntryTowers(cursor, entries, fallbackHost)
	return endpoints, nextHandle, nil
}

func parseEPMHeader(cursor *ndrCursor, nextHandle *[epmEntryHandleSize]byte) (int, error) {
	if len(cursor.buf) < epmLookupHeaderMinSize {
		return 0, fmt.Errorf("short epm stub")
	}

	maxCountRaw, ok := cursor.ReadUint32()
	if !ok {
		return 0, fmt.Errorf("short epm stub")
	}

	handleBytes, ok := cursor.ReadBytes(epmEntryHandleSize)
	if !ok {
		return 0, fmt.Errorf("short epm stub")
	}

	entryCountRaw, ok := cursor.ReadUint32()
	if !ok {
		return 0, fmt.Errorf("short epm stub")
	}

	_, ok = cursor.ReadUint32() // offset
	if !ok {
		return 0, fmt.Errorf("short epm stub")
	}

	actualCountRaw, ok := cursor.ReadUint32()
	if !ok {
		return 0, fmt.Errorf("short epm stub")
	}

	copy(nextHandle[:], handleBytes)
	maxCount := int(maxCountRaw)
	entryCount := int(entryCountRaw)
	actualCount := int(actualCountRaw)

	if actualCount < 0 || actualCount > epmMaxActualCount {
		return 0, fmt.Errorf("invalid epm actual_count: %d", actualCount)
	}
	if maxCount > 0 && actualCount > maxCount {
		actualCount = maxCount
	}
	if entryCount > 0 && actualCount > entryCount {
		actualCount = entryCount
	}

	return actualCount, nil
}

func parseEPMEntryRecords(cursor *ndrCursor, actualCount int) ([]epmEntryRecord, error) {
	entries := make([]epmEntryRecord, 0, actualCount)

	for i := 0; i < actualCount; i++ {
		if !cursor.Has(epmEntryFixedSize) {
			return nil, fmt.Errorf("short epm entry at index %d", i)
		}

		objectRaw, _ := cursor.ReadBytes(16)
		objectUUID := rpcBytesToUUIDString(objectRaw)
		towerRefRaw, _ := cursor.ReadUint32()
		_, _ = cursor.ReadUint32() // ann offset
		annotationLenRaw, _ := cursor.ReadUint32()

		annotationLen := int(annotationLenRaw)
		if annotationLen < 0 || !cursor.Has(annotationLen) {
			return nil, fmt.Errorf("invalid annotation length at index %d", i)
		}

		annotationRaw, _ := cursor.ReadBytes(annotationLen)
		annotation := sanitizeAnnotation(annotationRaw)
		cursor.Align4()

		entries = append(entries, epmEntryRecord{
			objectUUID: objectUUID,
			annotation: annotation,
			towerRef:   towerRefRaw,
		})
	}

	return entries, nil
}

func parseEPMEntryTowers(cursor *ndrCursor, entries []epmEntryRecord, fallbackHost string) []EPMEndpoint {
	endpoints := make([]EPMEndpoint, 0, len(entries))
	var ok bool

	for i := range entries {
		ep := EPMEndpoint{
			UUID:       entries[i].objectUUID,
			Annotation: entries[i].annotation,
		}

		if entries[i].towerRef != 0 {
			ep, ok = applyTowerData(cursor, ep, fallbackHost)
			if !ok {
				break
			}
		}

		if ep.UUID != "" || ep.Binding != "" || ep.Annotation != "" {
			endpoints = append(endpoints, ep)
		}
	}

	return endpoints
}

func applyTowerData(cursor *ndrCursor, ep EPMEndpoint, fallbackHost string) (EPMEndpoint, bool) {
	if !cursor.Has(ndrUint32Size * 2) {
		return ep, false
	}

	towerMaxCountRaw, _ := cursor.ReadUint32()
	towerLenRaw, _ := cursor.ReadUint32()
	towerLen := int(towerLenRaw)
	if towerLen < 0 {
		return ep, false
	}

	towerMaxCount := int(towerMaxCountRaw)
	dataLen := towerLen
	if dataLen > towerMaxCount && towerMaxCount > 0 {
		dataLen = towerMaxCount
	}

	if dataLen < 0 || !cursor.Has(dataLen) {
		return ep, false
	}

	towerData, _ := cursor.ReadBytes(dataLen)
	cursor.Align4()

	towerUUID, major, minor, binding, ok := parseTowerData(towerData, fallbackHost)
	if ok {
		if towerUUID != "" {
			ep.UUID = towerUUID
		}
		ep.Version = fmt.Sprintf("v%d.%d", major, minor)
		ep.Binding = binding
	}

	return ep, true
}

// parseTowerData decodes one RPC tower and extracts:
// interface UUID/version from floor 0 + transport binding from remaining floors.
func parseTowerData(data []byte, fallbackHost string) (string, uint16, uint16, string, bool) {
	cursor := newNDRCursor(data, 0)
	floorCountRaw, ok := cursor.ReadUint16()
	if !ok {
		return "", 0, 0, "", false
	}

	floorCount := int(floorCountRaw)
	if floorCount < towerMinFloorCount || floorCount > towerMaxFloorCount {
		return "", 0, 0, "", false
	}

	floors, _, ok := readTowerFloors(data, cursor.Pos(), floorCount, 0, 0)
	if !ok || len(floors) < towerMinFloorCount {
		return "", 0, 0, "", false
	}

	if !isInterfaceFloor(floors[0]) || !isInterfaceFloor(floors[1]) {
		return "", 0, 0, "", false
	}

	if len(floors[0].RHS) < 2 {
		return "", 0, 0, "", false
	}

	uuid := rpcBytesToUUIDString(floors[0].LHS[towerIfaceUUIDFrom:towerIfaceUUIDTo])
	major := binary.LittleEndian.Uint16(floors[0].LHS[towerIfaceMajorFrom:towerIfaceMajorTo])
	minor := binary.LittleEndian.Uint16(floors[0].RHS[towerIfaceMinorFrom:towerIfaceMinorTo])
	binding := floorsToBinding(floors[towerBindingFromFloor:], fallbackHost)
	return uuid, major, minor, binding, true
}

// align4 returns v aligned up to the next 4-byte boundary (NDR alignment rule).
func align4(v int) int {
	remainder := v % 4
	if remainder == 0 {
		return v
	}
	return v + (4 - remainder)
}

// parseTowers is a best-effort scanner over raw ept_lookup stubs.
// It is used when strict NDR decoding fails but useful tower data is still present.
func parseTowers(blob []byte, fallbackHost string) []parsedTower {
	results := make([]parsedTower, 0)

	for start := 0; start+4 < len(blob); start++ {
		floorCursor := newNDRCursor(blob, start)
		floorCountRaw, ok := floorCursor.ReadUint16()
		if !ok {
			continue
		}

		floorCount := int(floorCountRaw)
		if floorCount < towerMinFloorCount || floorCount > towerMaxFloorCount {
			continue
		}

		floors, endPos, ok := readTowerFloors(blob, floorCursor.Pos(), floorCount, towerScanMaxLHSLen, towerScanMaxRHSLen)
		if !ok || len(floors) < towerMinFloorCount {
			continue
		}
		if !isInterfaceFloor(floors[0]) {
			continue
		}
		if !isInterfaceFloor(floors[1]) {
			continue
		}
		if len(floors[0].RHS) < 2 {
			continue
		}

		uuid := rpcBytesToUUIDString(floors[0].LHS[towerIfaceUUIDFrom:towerIfaceUUIDTo])
		major := binary.LittleEndian.Uint16(floors[0].LHS[towerIfaceMajorFrom:towerIfaceMajorTo])
		minor := binary.LittleEndian.Uint16(floors[0].RHS[towerIfaceMinorFrom:towerIfaceMinorTo])
		binding := floorsToBinding(floors[towerBindingFromFloor:], fallbackHost)
		if uuid == "" { continue }

		results = append(results, parsedTower{
			Start:         start,
			End:           endPos,
			InterfaceUUID: uuid,
			VersionMajor:  major,
			VersionMinor:  minor,
			Binding:       binding,
		})
		start = endPos - 1
	}

	return results
}

func readTowerFloors(blob []byte, start int, floorCount int, maxLHSLen int, maxRHSLen int) ([]towerFloor, int, bool) {
	cursor := newNDRCursor(blob, start)
	floors := make([]towerFloor, 0, floorCount)

	for i := 0; i < floorCount; i++ {
		lhsLenRaw, ok := cursor.ReadUint16()
		if !ok {
			return nil, cursor.Pos(), false
		}

		lhsLen := int(lhsLenRaw)
		if lhsLen <= 0 || (maxLHSLen > 0 && lhsLen > maxLHSLen) || !cursor.Has(lhsLen) {
			return nil, cursor.Pos(), false
		}

		lhs, _ := cursor.ReadBytes(lhsLen)
		rhsLenRaw, ok := cursor.ReadUint16()
		if !ok {
			return nil, cursor.Pos(), false
		}

		rhsLen := int(rhsLenRaw)
		if rhsLen < 0 || (maxRHSLen > 0 && rhsLen > maxRHSLen) || !cursor.Has(rhsLen) {
			return nil, cursor.Pos(), false
		}

		rhs, _ := cursor.ReadBytes(rhsLen)

		floors = append(floors, towerFloor{LHS: lhs, RHS: rhs})
	}

	return floors, cursor.Pos(), true
}

func isInterfaceFloor(floor towerFloor) bool {
	return len(floor.LHS) == towerInterfaceLHSLen && floor.LHS[0] == towerInterfaceProtoID
}

// floorsToBinding translates transport/address tower floors into canonical binding strings.
// Examples: ncacn_ip_tcp:host[port], ncacn_np:host[\pipe\name], ncalrpc:[endpoint].
func floorsToBinding(floors []towerFloor, fallbackHost string) string {
	template := ""
	for _, floor := range floors {
		if len(floor.LHS) != 1 {
			continue
		}

		switch floor.LHS[0] {
		case towerIDIPTCP:
			if len(floor.RHS) >= 2 {
				port := binary.BigEndian.Uint16(floor.RHS[:2])
				template = fmt.Sprintf("ncacn_ip_tcp:%%s[%d]", port)
			}
		case towerIDIPUDP:
			if len(floor.RHS) >= 2 {
				port := binary.BigEndian.Uint16(floor.RHS[:2])
				template = fmt.Sprintf("ncadg_ip_udp:%%s[%d]", port)
			}
		case towerIDIPv4:
			if len(floor.RHS) == 4 {
				ip := net.IP(floor.RHS).String()
				if template != "" {
					return fmt.Sprintf(template, ip)
				}
				return "IP: " + ip
			}
		case towerIDNP:
			pipe := trimNullASCII(floor.RHS)
			template = fmt.Sprintf("ncacn_np:%%s[%s]", pipe)
		case towerIDLRPC:
			name := trimNullASCII(floor.RHS)
			return fmt.Sprintf("ncalrpc:[%s]", name)
		case towerIDNBName, towerIDNBHost:
			host := trimNullASCII(floor.RHS)
			if template != "" {
				return fmt.Sprintf(template, host)
			}
			return "NetBIOS: " + host
		case towerIDHTTP:
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

// sanitizeAnnotation filters noisy/non-printable annotations to keep usable labels.
func sanitizeAnnotation(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}

	annotation := strings.TrimRight(string(raw), "\x00")
	annotation = strings.TrimSpace(annotation)
	if !looksLikeAnnotation(annotation) {
		return ""
	}
	return annotation
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

		candidate := strings.TrimSpace(string(blob[i:j]))
		if looksLikeAnnotation(candidate) && !found[candidate] {
			found[candidate] = true
			out = append(out, candidate)
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

	lower := strings.ToLower(s)
	if strings.Contains(lower, "ncacn_") || strings.Contains(lower, "\\pipe\\") {
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
	normalized := make([]EPMEndpoint, 0, len(input))
	indexByKey := make(map[string]int, len(input))

	for _, ep := range input {
		ep = normalizeEndpointFields(ep)
		if ep.UUID == "" && ep.Binding == "" && ep.Annotation == "" {
			continue
		}

		key := endpointMergeKey(ep)
		idx, exists := indexByKey[key]
		if !exists {
			indexByKey[key] = len(normalized)
			normalized = append(normalized, ep)
			continue
		}

		normalized[idx] = mergeEndpointVariants(normalized[idx], ep)
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

func normalizeEndpointFields(ep EPMEndpoint) EPMEndpoint {
	ep.UUID = strings.ToLower(strings.TrimSpace(ep.UUID))
	ep.Version = strings.TrimSpace(ep.Version)
	ep.Binding = strings.TrimSpace(ep.Binding)
	ep.Annotation = sanitizeAnnotation([]byte(ep.Annotation))
	return ep
}

func endpointMergeKey(ep EPMEndpoint) string {
	key := ep.UUID + "|" + ep.Binding
	if key == "|" {
		key = ep.UUID + "|" + ep.Annotation
	}
	return key
}

func mergeEndpointVariants(current EPMEndpoint, candidate EPMEndpoint) EPMEndpoint {
	if current.Version == "" && candidate.Version != "" {
		current.Version = candidate.Version
	}
	if annotationScore(candidate.Annotation) > annotationScore(current.Annotation) {
		current.Annotation = candidate.Annotation
	}
	if current.UUID == "" && candidate.UUID != "" {
		current.UUID = candidate.UUID
	}
	if current.Binding == "" && candidate.Binding != "" {
		current.Binding = candidate.Binding
	}
	return current
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
func isZeroEntryHandle(h [epmEntryHandleSize]byte) bool {
	for _, b := range h {
		if b != 0 {
			return false
		}
	}
	return true
}
