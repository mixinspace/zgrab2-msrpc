package msrpc

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

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
	epmNullUUID            = "00000000-0000-0000-0000-000000000000"

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

type epmParsedRecord struct {
	objectUUID    string
	interfaceUUID string
	versionMajor  uint16
	versionMinor  uint16
	binding       string
	annotation    string
}

type epmLookupEntry struct {
	Name     string           `json:"name"`
	Protocol string           `json:"protocol"`
	Provider string           `json:"provider"`
	Sources  epmLookupSources `json:"sources"`
}

type epmLookupStrings []string

func (s *epmLookupStrings) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		*s = nil
		return nil
	}

	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		single = strings.TrimSpace(single)
		if single == "" {
			*s = nil
		} else {
			*s = []string{single}
		}
		return nil
	}

	var many []string
	if err := json.Unmarshal(data, &many); err == nil {
		out := make([]string, 0, len(many))
		for _, item := range many {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			out = append(out, item)
		}
		*s = out
		return nil
	}

	return fmt.Errorf("unsupported epm source string shape")
}

type epmLookupFieldSource struct {
	IsOfficial  bool             `json:"is_official"`
	Description epmLookupStrings `json:"description"`
	References  epmLookupStrings `json:"reference"`
}

type epmLookupSources struct {
	Name     *epmLookupFieldSource `json:"name"`
	Protocol *epmLookupFieldSource `json:"protocol"`
	Provider *epmLookupFieldSource `json:"provider"`
}

var (
	//go:embed data/full_db.json
	epmLookupJSON []byte

	epmLookup     map[string]epmLookupEntry
	epmLookupErr  error
	epmLookupOnce sync.Once
)

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
	result := &EPMResult{
		Interfaces: make([]EPMInterface, 0),
		Unresolved: make([]EPMUnresolved, 0),
	}

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
	result := &EPMResult{
		Interfaces: make([]EPMInterface, 0),
		Unresolved: make([]EPMUnresolved, 0),
	}
	callID := uint32(2)
	var entryHandle [epmEntryHandleSize]byte
	hadResponse := false
	fallbackHost := target.Host()
	records := make([]epmParsedRecord, 0)

	for page := 0; page < maxEPMPages; page++ {
		requestStub := buildEptLookupStub(entryHandle, uint32(s.config.MaxEntries))
		requestCallID := callID
		requestPDU := buildRequestPDU(requestCallID, 0, 2, requestStub)
		callID++

		pdu, err := s.sendAndRecvRPC(conn, requestPDU, requestCallID)
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

		parsedRecords, nextHandle, parseErr := parseEPMEntries(responseStub, fallbackHost)
		if parseErr != nil {
			// Best-effort extraction if strict NDR parsing fails.
			updateEntryHandleFromStub(responseStub, &entryHandle)
			records = append(records, parsedRecords...)
			records = append(records, buildFallbackRecords(responseStub, fallbackHost)...)
		} else {
			entryHandle = nextHandle
			records = append(records, parsedRecords...)
		}

		if isZeroEntryHandle(entryHandle) {
			break
		}
	}

	interfaces, unresolved := aggregateEPMRecords(records)
	interfaces = enrichEPM(interfaces, s.config.EPMPolicy)
	result.Interfaces = interfaces
	result.Unresolved = unresolved
	result.Success = hadResponse
	result.InterfaceCount = len(interfaces)
	result.UnresolvedCount = len(unresolved)
	return result, nil
}

func validateEPMLookupResponsePDU(pdu *rpcMessage) error {
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

// buildEptLookupStub builds parameters for ept_lookup:
// inquiry_type=0, object=nil, interface_id=nil, vers_option=1, entry_handle, max_ents.
func buildEptLookupStub(entryHandle [epmEntryHandleSize]byte, maxEnts uint32) []byte {
	body := &bytes.Buffer{}
	_ = binary.Write(body, binary.LittleEndian, uint32(0))
	_ = binary.Write(body, binary.LittleEndian, uint32(0))
	_ = binary.Write(body, binary.LittleEndian, uint32(0))
	_ = binary.Write(body, binary.LittleEndian, uint32(1))
	body.Write(entryHandle[:])
	_ = binary.Write(body, binary.LittleEndian, maxEnts)
	return body.Bytes()
}

func readEPMEntryHandle(cursor *ndrCursor) ([epmEntryHandleSize]byte, bool) {
	var handle [epmEntryHandleSize]byte

	handleBytes, ok := cursor.ReadBytes(epmEntryHandleSize)
	if !ok {
		return handle, false
	}

	copy(handle[:], handleBytes)
	return handle, true
}

func updateEntryHandleFromStub(stub []byte, entryHandle *[epmEntryHandleSize]byte) {
	cursor := newNDRCursor(stub, 0)
	handle, ok := readEPMEntryHandle(cursor)
	if ok {
		*entryHandle = handle
	}
}

func buildFallbackRecords(stub []byte, fallbackHost string) []epmParsedRecord {
	towers := parseTowers(stub, fallbackHost)
	annotations := extractAnnotations(stub)

	records := make([]epmParsedRecord, 0, len(towers))
	for i := range towers {
		record := epmParsedRecord{
			interfaceUUID: towers[i].InterfaceUUID,
			versionMajor:  towers[i].VersionMajor,
			versionMinor:  towers[i].VersionMinor,
			binding:       towers[i].Binding,
		}
		if i < len(annotations) {
			record.annotation = sanitizeAnnotation([]byte(annotations[i]))
		}
		records = append(records, record)
	}
	return records
}

// parseEPMEntries decodes the NDR body returned by ept_lookup.
// Structure (simplified):
//   - next_entry_handle
//   - count fields for the entry array
//   - entries array with object UUID / annotation / tower reference
//   - concatenated tower blobs
func parseEPMEntries(stub []byte, fallbackHost string) ([]epmParsedRecord, [epmEntryHandleSize]byte, error) {
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

	records, err := parseEPMEntryTowers(cursor, entries, fallbackHost)
	if err != nil {
		return records, nextHandle, err
	}
	return records, nextHandle, nil
}

func parseEPMHeader(cursor *ndrCursor, nextHandle *[epmEntryHandleSize]byte) (int, error) {
	if len(cursor.buf) < epmLookupHeaderMinSize {
		return 0, fmt.Errorf("short epm stub")
	}

	handleBytes, ok := readEPMEntryHandle(cursor)
	if !ok {
		return 0, fmt.Errorf("short epm stub")
	}

	maxCountRaw, ok := cursor.ReadUint32()
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

	*nextHandle = handleBytes
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

func parseEPMEntryTowers(cursor *ndrCursor, entries []epmEntryRecord, fallbackHost string) ([]epmParsedRecord, error) {
	records := make([]epmParsedRecord, 0, len(entries))

	for i := range entries {
		record := epmParsedRecord{
			objectUUID: entries[i].objectUUID,
			annotation: entries[i].annotation,
		}

		if entries[i].towerRef != 0 {
			parsedRecord, ok := applyTowerData(cursor, record, fallbackHost)
			if !ok {
				return records, fmt.Errorf("short epm tower at index %d", i)
			}
			record = parsedRecord
		}

		if hasRecordData(record) {
			records = append(records, record)
		}
	}

	return records, nil
}

func hasRecordData(record epmParsedRecord) bool {
	return record.objectUUID != "" ||
		record.interfaceUUID != "" ||
		record.binding != "" ||
		record.annotation != ""
}

func applyTowerData(cursor *ndrCursor, record epmParsedRecord, fallbackHost string) (epmParsedRecord, bool) {
	if !cursor.Has(ndrUint32Size * 2) {
		return record, false
	}

	towerMaxCountRaw, _ := cursor.ReadUint32()
	towerLenRaw, _ := cursor.ReadUint32()
	towerLen := int(towerLenRaw)
	if towerLen < 0 {
		return record, false
	}

	towerMaxCount := int(towerMaxCountRaw)
	dataLen := towerLen
	if dataLen > towerMaxCount && towerMaxCount > 0 {
		dataLen = towerMaxCount
	}

	if dataLen < 0 || !cursor.Has(dataLen) {
		return record, false
	}

	towerData, _ := cursor.ReadBytes(dataLen)
	cursor.Align4()

	towerUUID, major, minor, binding, ok := parseTowerData(towerData, fallbackHost)
	if ok {
		record.interfaceUUID = towerUUID
		record.versionMajor = major
		record.versionMinor = minor
		record.binding = binding
	}

	return record, true
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
		if uuid == "" {
			continue
		}

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
		if looksLikeAnnotation(candidate) {
			out = append(out, candidate)
		}
		i = j
	}

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

func aggregateEPMRecords(input []epmParsedRecord) ([]EPMInterface, []EPMUnresolved) {
	type interfaceAccumulator struct {
		interfaceUUID string
		version       string
		bindings      map[string]struct{}
		objectUUIDs   map[string]struct{}
		annotations   map[string]struct{}
	}
	type unresolvedKey struct {
		objectUUID string
		binding    string
		annotation string
	}

	accumulators := make(map[string]*interfaceAccumulator)
	unresolvedSet := make(map[unresolvedKey]struct{})
	unresolved := make([]EPMUnresolved, 0)

	for _, raw := range input {
		record := normalizeParsedRecord(raw)
		if record.interfaceUUID != "" {
			version := formatEPMVersion(record.versionMajor, record.versionMinor)
			key := record.interfaceUUID + "|" + version

			acc, found := accumulators[key]
			if !found {
				acc = &interfaceAccumulator{
					interfaceUUID: record.interfaceUUID,
					version:       version,
					bindings:      make(map[string]struct{}),
					objectUUIDs:   make(map[string]struct{}),
					annotations:   make(map[string]struct{}),
				}
				accumulators[key] = acc
			}

			if record.binding != "" {
				acc.bindings[record.binding] = struct{}{}
			}
			if record.objectUUID != "" {
				acc.objectUUIDs[record.objectUUID] = struct{}{}
			}
			if record.annotation != "" {
				acc.annotations[record.annotation] = struct{}{}
			}
			continue
		}

		if record.objectUUID != "" || record.binding != "" || record.annotation != "" {
			item := EPMUnresolved{
				ObjectUUID: record.objectUUID,
				Binding:    record.binding,
				Annotation: record.annotation,
			}
			key := unresolvedKey{
				objectUUID: item.ObjectUUID,
				binding:    item.Binding,
				annotation: item.Annotation,
			}
			if _, exists := unresolvedSet[key]; !exists {
				unresolvedSet[key] = struct{}{}
				unresolved = append(unresolved, item)
			}
		}
	}

	interfaces := make([]EPMInterface, 0, len(accumulators))
	for _, acc := range accumulators {
		interfaces = append(interfaces, EPMInterface{
			InterfaceUUID: acc.interfaceUUID,
			Version:       acc.version,
			Bindings:      mapKeysSorted(acc.bindings),
			ObjectUUIDs:   mapKeysSorted(acc.objectUUIDs),
			Annotations:   mapKeysSorted(acc.annotations),
		})
	}

	sort.Slice(interfaces, func(i, j int) bool {
		if interfaces[i].InterfaceUUID != interfaces[j].InterfaceUUID {
			return interfaces[i].InterfaceUUID < interfaces[j].InterfaceUUID
		}
		return interfaces[i].Version < interfaces[j].Version
	})

	sort.Slice(unresolved, func(i, j int) bool {
		if unresolved[i].ObjectUUID != unresolved[j].ObjectUUID {
			return unresolved[i].ObjectUUID < unresolved[j].ObjectUUID
		}
		if unresolved[i].Binding != unresolved[j].Binding {
			return unresolved[i].Binding < unresolved[j].Binding
		}
		return unresolved[i].Annotation < unresolved[j].Annotation
	})

	return interfaces, unresolved
}

func enrichEPM(input []EPMInterface, policy string) []EPMInterface {
	if len(input) == 0 {
		return input
	}

	lookup, err := loadEPMLookup()
	if err != nil || len(lookup) == 0 {
		return input
	}

	for i := range input {
		interfaceUUID := strings.ToLower(strings.TrimSpace(input[i].InterfaceUUID))
		if interfaceUUID == "" {
			continue
		}

		entry, found := lookup[interfaceUUID]
		if !found {
			continue
		}

		if shouldApplyEPMEnrichmentField(entry.Name, entry.Sources.Name, policy) {
			input[i].Name = entry.Name
		}
		if shouldApplyEPMEnrichmentField(entry.Protocol, entry.Sources.Protocol, policy) {
			input[i].Protocol = entry.Protocol
		}
		if shouldApplyEPMEnrichmentField(entry.Provider, entry.Sources.Provider, policy) {
			input[i].Provider = entry.Provider
		}
	}

	return input
}

func shouldApplyEPMEnrichmentField(value string, source *epmLookupFieldSource, policy string) bool {
	if value == "" {
		return false
	}
	if policy != epmPolicyVerified {
		return true
	}
	return source != nil && source.IsOfficial
}

func loadEPMLookup() (map[string]epmLookupEntry, error) {
	epmLookupOnce.Do(func() {
		raw := make(map[string]epmLookupEntry)
		if err := json.Unmarshal(epmLookupJSON, &raw); err != nil {
			epmLookupErr = err
			return
		}

		normalized := make(map[string]epmLookupEntry, len(raw))
		for interfaceUUID, entry := range raw {
			key := strings.ToLower(strings.TrimSpace(interfaceUUID))
			if key == "" {
				continue
			}
			normalized[key] = entry
		}

		epmLookup = normalized
	})

	return epmLookup, epmLookupErr
}

func normalizeParsedRecord(record epmParsedRecord) epmParsedRecord {
	record.objectUUID = strings.ToLower(strings.TrimSpace(record.objectUUID))
	if record.objectUUID == epmNullUUID {
		record.objectUUID = ""
	}
	record.interfaceUUID = strings.ToLower(strings.TrimSpace(record.interfaceUUID))
	record.binding = strings.TrimSpace(record.binding)
	record.annotation = sanitizeAnnotation([]byte(record.annotation))
	return record
}

func formatEPMVersion(major, minor uint16) string {
	return fmt.Sprintf("v%d.%d", major, minor)
}

func mapKeysSorted(source map[string]struct{}) []string {
	if len(source) == 0 {
		return nil
	}
	out := make([]string, 0, len(source))
	for key := range source {
		if key == "" {
			continue
		}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
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
