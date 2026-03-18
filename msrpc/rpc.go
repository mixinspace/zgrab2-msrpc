package msrpc

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// performBind sends a connection-oriented DCE/RPC BIND PDU and parses the BIND_ACK/BIND_NAK.
// It also extracts optional NTLM challenge metadata from the auth trailer when present.
func (s *Scanner) performBind(conn net.Conn, ifaceUUID string, versMajor, versMinor uint16, callID uint32, ntlmToken []byte) (*BindResult, *rpcPDU, error) {
	req, err := buildBindPDU(ifaceUUID, versMajor, versMinor, callID, ntlmToken)
	if err != nil {
		return &BindResult{Error: err.Error()}, nil, err
	}
	pdu, err := s.sendAndRecvRPC(conn, req)
	if err != nil {
		return &BindResult{Error: err.Error()}, nil, err
	}

	res := &BindResult{
		ResponsePDU: &ResponsePDU{
			Code: pdu.Type,
			Name: rpcPacketTypeName(pdu.Type),
		},
	}
	if pdu.Type == rpcPTYPEBindNak {
		res.Error = "bind nack"
		return res, pdu, fmt.Errorf("received bind_nak")
	}
	if pdu.Type != rpcPTYPEBindAck {
		res.Error = fmt.Sprintf("unexpected packet type %d", pdu.Type)
		return res, pdu, fmt.Errorf(res.Error)
	}
	if len(pdu.Body) < 10 {
		res.Error = "short bind_ack body"
		return res, pdu, fmt.Errorf(res.Error)
	}

	// BIND_ACK layout starts with max fragments, association group, then secondary address.
	res.AssociationGroupID = binary.LittleEndian.Uint32(pdu.Body[4:8])
	secAddrLen := int(binary.LittleEndian.Uint16(pdu.Body[8:10]))
	if secAddrLen > 0 && 10+secAddrLen <= len(pdu.Body) {
		raw := strings.TrimRight(string(pdu.Body[10:10+secAddrLen]), "\x00")
		ep := &SecondaryEndpoint{Raw: raw}
		if port, convErr := strconv.Atoi(raw); convErr == nil && port >= 0 && port <= 65535 {
			ep.Port = uint16(port)
		}
		res.SecondaryEndpoint = ep
	}
	pos := 10 + secAddrLen
	pos += (4 - (pos % 4)) % 4
	accepted := true
	if pos+4 <= len(pdu.Body) {
		// p_result_list_t: one result per presentation context we proposed in the BIND.
		numResults := int(pdu.Body[pos])
		pos += 4
		if numResults > 0 && pos+24 <= len(pdu.Body) {
			res.ContextResult = binary.LittleEndian.Uint16(pdu.Body[pos : pos+2])
			res.ContextReason = binary.LittleEndian.Uint16(pdu.Body[pos+2 : pos+4])
			if res.ContextResult != 0 {
				accepted = false
			}
		}
	}

	if pdu.AuthLen > 0 || len(ntlmToken) > 0 {
		ch, _ := parseNTLMChallengeFromPDU(pdu.Raw)
		res.NTLMChallenge = ch
	}
	res.Accepted = accepted
	if !accepted {
		if res.Error == "" {
			res.Error = fmt.Sprintf("bind context rejected (result=%d reason=%d)", res.ContextResult, res.ContextReason)
		}
		return res, pdu, fmt.Errorf(res.Error)
	}
	return res, pdu, nil
}

// rpcPacketTypeName returns a human-readable DCE/RPC PTYPE name.
func rpcPacketTypeName(ptype uint8) string {
	switch ptype {
	case rpcPTYPEBindAck:
		return "bind_ack"
	case rpcPTYPEBindNak:
		return "bind_nak"
	case rpcPTYPERequest:
		return "request"
	case rpcPTYPEResponse:
		return "response"
	case rpcPTYPEFault:
		return "fault"
	case rpcPTYPEBind:
		return "bind"
	default:
		return "unknown"
	}
}

func parseRPCFaultStatus(body []byte) (uint32, bool) {
	// Fault PDU body (connection-oriented) encodes status at offset 8.
	if len(body) < 12 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(body[8:12]), true
}

// rpcFaultStatusName maps frequently observed RPC fault status values to canonical names.
func rpcFaultStatusName(status uint32) string {
	switch status {
	case rpcFaultNCAOpRangeError:
		return "nca_s_op_rng_error"
	case rpcFaultNCAUnknownIf:
		return "nca_s_unk_if"
	case rpcFaultNCAProtoError:
		return "nca_s_proto_error"
	case rpcFaultAccessDenied:
		return "access_denied"
	default:
		return "unknown"
	}
}

// sendAndRecvRPC writes one RPC PDU and reads one RPC PDU using module read/write timeouts.
func (s *Scanner) sendAndRecvRPC(conn net.Conn, request []byte) (*rpcPDU, error) {
	timeout := time.Duration(s.config.ReadTimeout) * time.Millisecond
	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}
	conn.SetReadDeadline(time.Now().Add(timeout))
	return readRPCPDU(conn, s.config.MaxReadSize*1024)
}

// readRPCPDU reads a single connection-oriented DCE/RPC fragment.
// This scanner sends FIRST|LAST PDUs, so one fragment normally equals one complete message.
// maxBytes is an upper bound on the fragment length (including 16-byte header).
func readRPCPDU(conn net.Conn, maxBytes int) (*rpcPDU, error) {
	header := make([]byte, 16)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	fragLen := int(binary.LittleEndian.Uint16(header[8:10]))
	if fragLen < 16 {
		return nil, fmt.Errorf("invalid fragment length: %d", fragLen)
	}
	if fragLen > maxBytes {
		return nil, fmt.Errorf("fragment length %d exceeds limit %d", fragLen, maxBytes)
	}
	bodyLen := fragLen - 16
	body := make([]byte, bodyLen)
	if bodyLen > 0 {
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, err
		}
	}
	raw := append(header, body...)
	return &rpcPDU{
		Version: header[0],
		Minor:   header[1],
		Type:    header[2],
		Flags:   header[3],
		FragLen: binary.LittleEndian.Uint16(header[8:10]),
		AuthLen: binary.LittleEndian.Uint16(header[10:12]),
		CallID:  binary.LittleEndian.Uint32(header[12:16]),
		Body:    body,
		Raw:     raw,
	}, nil
}

// buildRPCHeader encodes the fixed 16-byte connection-oriented RPC header:
// version, ptype, flags, data representation, frag_len, auth_len, call_id.
func buildRPCHeader(ptype uint8, callID uint32, bodyLen int, authLen uint16) []byte {
	h := make([]byte, 16)
	h[0] = rpcVersionMajor
	h[1] = rpcVersionMinor
	h[2] = ptype
	h[3] = rpcFlagFirstFrag | rpcFlagLastFrag
	h[4] = rpcDataRepLE
	h[5] = 0x00
	h[6] = 0x00
	h[7] = 0x00
	binary.LittleEndian.PutUint16(h[8:10], uint16(16+bodyLen))
	binary.LittleEndian.PutUint16(h[10:12], authLen)
	binary.LittleEndian.PutUint32(h[12:16], callID)
	return h
}

// buildBindPDU constructs a BIND request with one context item:
// requested interface UUID/version + NDR transfer syntax UUID/version.
// If ntlmToken is provided, it appends sec_trailer + auth_value (NTLMSSP token).
func buildBindPDU(ifaceUUID string, ifaceMajor, ifaceMinor uint16, callID uint32, ntlmToken []byte) ([]byte, error) {
	iface, err := uuidStringToRPCBytes(ifaceUUID)
	if err != nil {
		return nil, err
	}
	transfer, err := uuidStringToRPCBytes(uuidNDRTransferSyntax)
	if err != nil {
		return nil, err
	}

	body := &bytes.Buffer{}
	// bind PDU common fields
	_ = binary.Write(body, binary.LittleEndian, uint16(defaultMaxFragment))
	_ = binary.Write(body, binary.LittleEndian, uint16(defaultMaxFragment))
	_ = binary.Write(body, binary.LittleEndian, uint32(0))
	// presentation context list: exactly one item
	body.WriteByte(1)
	body.Write([]byte{0x00, 0x00, 0x00})
	_ = binary.Write(body, binary.LittleEndian, uint16(0))
	body.WriteByte(1)
	body.WriteByte(0)
	// abstract syntax (target interface)
	body.Write(iface[:])
	_ = binary.Write(body, binary.LittleEndian, ifaceMajor)
	_ = binary.Write(body, binary.LittleEndian, ifaceMinor)
	// transfer syntax (NDR v2)
	body.Write(transfer[:])
	_ = binary.Write(body, binary.LittleEndian, uint16(2))
	_ = binary.Write(body, binary.LittleEndian, uint16(0))

	authLen := uint16(0)
	if len(ntlmToken) > 0 {
		padLen := (4 - (body.Len() % 4)) % 4
		if padLen > 0 {
			body.Write(make([]byte, padLen))
		}
		secTrailer := []byte{
			rpcAuthTypeNTLM,
			rpcAuthLevelConn,
			byte(padLen),
			0x00,
			0x00, 0x00, 0x00, 0x00,
		}
		body.Write(secTrailer)
		body.Write(ntlmToken)
		authLen = uint16(len(ntlmToken))
	}

	header := buildRPCHeader(rpcPTYPEBind, callID, body.Len(), authLen)
	return append(header, body.Bytes()...), nil
}

// buildRequestPDU constructs a REQUEST PDU with alloc_hint/context_id/opnum + optional stub.
func buildRequestPDU(callID uint32, contextID uint16, opnum uint16, stub []byte) []byte {
	body := &bytes.Buffer{}
	_ = binary.Write(body, binary.LittleEndian, uint32(len(stub)))
	_ = binary.Write(body, binary.LittleEndian, contextID)
	_ = binary.Write(body, binary.LittleEndian, opnum)
	if len(stub) > 0 {
		body.Write(stub)
	}
	header := buildRPCHeader(rpcPTYPERequest, callID, body.Len(), 0)
	return append(header, body.Bytes()...)
}

// buildEptLookupStub builds parameters for ept_lookup:
// inquiry_type=0, object=nil, interface_id=nil, vers_option=1, entry_handle, max_ents.
func buildEptLookupStub(entryHandle [20]byte, maxEnts uint32) []byte {
	body := &bytes.Buffer{}
	_ = binary.Write(body, binary.LittleEndian, uint32(0))
	_ = binary.Write(body, binary.LittleEndian, uint32(0))
	_ = binary.Write(body, binary.LittleEndian, uint32(0))
	_ = binary.Write(body, binary.LittleEndian, uint32(1))
	body.Write(entryHandle[:])
	_ = binary.Write(body, binary.LittleEndian, maxEnts)
	return body.Bytes()
}

// parseResponseStub strips the 8-byte RESPONSE header prefix
// (alloc_hint + context_id + cancel_count/opnum padding) and returns the NDR stub payload.
func parseResponseStub(body []byte) ([]byte, error) {
	if len(body) < 8 {
		return nil, fmt.Errorf("short response body")
	}
	return body[8:], nil
}

// uuidStringToRPCBytes converts a canonical UUID string to RPC wire byte order
// (little-endian for first 3 fields, network order for last 2).
func uuidStringToRPCBytes(uuid string) ([16]byte, error) {
	var out [16]byte
	parts := strings.Split(strings.ToLower(strings.TrimSpace(uuid)), "-")
	if len(parts) != 5 {
		return out, fmt.Errorf("invalid uuid: %s", uuid)
	}
	p0, err := hex.DecodeString(parts[0])
	if err != nil || len(p0) != 4 {
		return out, fmt.Errorf("invalid uuid: %s", uuid)
	}
	p1, err := hex.DecodeString(parts[1])
	if err != nil || len(p1) != 2 {
		return out, fmt.Errorf("invalid uuid: %s", uuid)
	}
	p2, err := hex.DecodeString(parts[2])
	if err != nil || len(p2) != 2 {
		return out, fmt.Errorf("invalid uuid: %s", uuid)
	}
	p3, err := hex.DecodeString(parts[3])
	if err != nil || len(p3) != 2 {
		return out, fmt.Errorf("invalid uuid: %s", uuid)
	}
	p4, err := hex.DecodeString(parts[4])
	if err != nil || len(p4) != 6 {
		return out, fmt.Errorf("invalid uuid: %s", uuid)
	}

	out[0] = p0[3]
	out[1] = p0[2]
	out[2] = p0[1]
	out[3] = p0[0]
	out[4] = p1[1]
	out[5] = p1[0]
	out[6] = p2[1]
	out[7] = p2[0]
	copy(out[8:10], p3)
	copy(out[10:16], p4)
	return out, nil
}

// rpcBytesToUUIDString converts 16-byte RPC wire UUID format to canonical string form.
func rpcBytesToUUIDString(raw []byte) string {
	if len(raw) < 16 {
		return ""
	}
	return fmt.Sprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		raw[3], raw[2], raw[1], raw[0],
		raw[5], raw[4],
		raw[7], raw[6],
		raw[8], raw[9],
		raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
	)
}
