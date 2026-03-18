package msrpc

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
)

// performIOXIDLookupConn runs IObjectExporter::ServerAlive2 on an existing RPC association:
// 1) bind to IObjectExporter interface
// 2) call opnum 5 (ServerAlive2)
// 3) parse returned dual-string bindings into normalized fields.
func (s *Scanner) performIOXIDLookupConn(conn net.Conn) (*IOXIDResult, *BindResult, error) {
	ret := &IOXIDResult{}
	bindCallID := uint32(1)
	bind, _, err := s.performBind(conn, uuidIObjectExporter, 0, 0, bindCallID, nil)
	if err != nil {
		return ret, bind, err
	}
	if bind == nil || !bind.Accepted {
		return ret, bind, fmt.Errorf("iobjectexporter bind failed")
	}

	req := buildRequestPDU(bindCallID+1, 0, 5, nil)
	pdu, err := s.sendAndRecvRPC(conn, req)
	if err != nil {
		return ret, bind, err
	}
	if pdu.Type == rpcPTYPEFault {
		status, ok := parseRPCFaultStatus(pdu.Body)
		if ok {
			return ret, bind, fmt.Errorf("ioxresolver ServerAlive2 fault: %s (0x%08x)", rpcFaultStatusName(status), status)
		}
		return ret, bind, fmt.Errorf("ioxresolver ServerAlive2 fault")
	}
	if pdu.Type != rpcPTYPEResponse {
		return ret, bind, fmt.Errorf("unexpected IOXID response packet type: %d", pdu.Type)
	}
	stub, err := parseResponseStub(pdu.Body)
	if err != nil {
		return ret, bind, err
	}

	if len(stub) >= 4 {
		major := binary.LittleEndian.Uint16(stub[0:2])
		minor := binary.LittleEndian.Uint16(stub[2:4])
		ret.COMVersion = fmt.Sprintf("%d.%d", major, minor)
	}
	ret.Bindings = parseDualStringBindings(stub)
	ret.IPv4 = uniqueSorted(extractIPv4(ret.Bindings))
	ret.IPv6 = uniqueSorted(extractIPv6(ret.Bindings))
	ret.Hostnames = uniqueSorted(extractHostnames(ret.Bindings))
	ret.Success = true
	return ret, bind, nil
}

// parseDualStringBindings extracts tower entries from the ServerAlive2 dual-string array.
// Parsing is strict enough to avoid random binary fragments (known tower IDs + ASCII-like UTF-16).
func parseDualStringBindings(blob []byte) []string {
	seen := make(map[string]bool)
	out := make([]string, 0)
	for i := 0; i+4 <= len(blob); i += 2 {
		towerID := binary.LittleEndian.Uint16(blob[i : i+2])
		if !isLikelyTowerID(towerID) {
			continue
		}
		addr, next, ok := readUTF16Z(blob, i+2)
		if !ok || addr == "" {
			continue
		}
		binding := formatTowerBinding(towerID, addr)
		if binding == "" || seen[binding] {
			continue
		}
		seen[binding] = true
		out = append(out, binding)
		i = next
	}
	sort.Strings(out)
	return out
}

// isLikelyTowerID whitelists protocol IDs commonly seen in IOXID dual-string bindings.
func isLikelyTowerID(id uint16) bool {
	switch id {
	case 0x07, 0x08, 0x0F, 0x10, 0x11, 0x1F:
		return true
	default:
		return false
	}
}

// formatTowerBinding maps tower protocol IDs to canonical endpoint strings.
func formatTowerBinding(towerID uint16, addr string) string {
	addr = strings.TrimSpace(addr)
	switch towerID {
	case 0x07:
		return "ncacn_ip_tcp:" + addr
	case 0x08:
		return "ncadg_ip_udp:" + addr
	case 0x0F:
		return "ncacn_np:" + addr
	case 0x10:
		return "ncalrpc:[" + addr + "]"
	case 0x1F:
		return "ncacn_http:" + addr
	case 0x11:
		return "NetBIOS: " + addr
	default:
		return ""
	}
}

// extractIPv4 collects IPv4 literals from parsed binding strings.
func extractIPv4(bindings []string) []string {
	out := make([]string, 0)
	for _, b := range bindings {
		matches := ipv4Regex.FindAllString(b, -1)
		out = append(out, matches...)
	}
	return out
}

// extractIPv6 collects IPv6-like tokens from parsed binding strings.
func extractIPv6(bindings []string) []string {
	out := make([]string, 0)
	for _, b := range bindings {
		matches := ipv6Regex.FindAllString(b, -1)
		for _, m := range matches {
			if strings.Count(m, ":") >= 2 {
				out = append(out, m)
			}
		}
	}
	return out
}

// extractHostnames collects non-IP host tokens from parsed binding strings.
func extractHostnames(bindings []string) []string {
	out := make([]string, 0)
	for _, b := range bindings {
		idx := strings.IndexByte(b, ':')
		if idx < 0 || idx+1 >= len(b) {
			continue
		}
		rest := b[idx+1:]
		rest = strings.TrimPrefix(rest, "[")
		rest = strings.TrimSuffix(rest, "]")
		if pos := strings.Index(rest, "["); pos >= 0 {
			rest = rest[:pos]
		}
		if net.ParseIP(rest) == nil && looksLikeHost(rest) {
			out = append(out, rest)
		}
	}
	return out
}

// looksLikeHost applies a permissive ASCII hostname token check.
func looksLikeHost(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_' {
			continue
		}
		return false
	}
	return true
}

// readUTF16Z reads a NUL-terminated UTF-16LE string at offset.
// It intentionally accepts only printable ASCII-range code points to reduce false positives.
func readUTF16Z(blob []byte, offset int) (string, int, bool) {
	if offset < 0 || offset >= len(blob) {
		return "", offset, false
	}
	chars := make([]uint16, 0, 64)
	i := offset
	for i+2 <= len(blob) {
		v := binary.LittleEndian.Uint16(blob[i : i+2])
		i += 2
		if v == 0 {
			break
		}
		if v < 0x20 || v > 0x7e {
			return "", i, false
		}
		chars = append(chars, v)
		if len(chars) > 256 {
			return "", i, false
		}
	}
	if len(chars) == 0 {
		return "", i, false
	}
	runes := make([]rune, len(chars))
	for idx, v := range chars {
		runes[idx] = rune(v)
	}
	return string(runes), i, true
}

// uniqueSorted returns a sorted de-duplicated list with empty entries removed.
func uniqueSorted(values []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0)
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
