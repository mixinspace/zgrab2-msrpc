package msrpc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/zmap/zgrab2/lib/smb/ntlmssp"
	smbencoder "github.com/zmap/zgrab2/lib/smb/smb/encoder"
)

func buildNTLMNegotiateToken() ([]byte, error) {
	neg := ntlmssp.NewNegotiate("", "")
	return smbencoder.Marshal(neg)
}

func parseNTLMChallengeFromPDU(raw []byte) (*NTLMChallenge, error) {
	idx := bytes.Index(raw, []byte(ntlmssp.Signature))
	if idx < 0 {
		return nil, nil
	}
	chal := ntlmssp.NewChallenge()
	if err := smbencoder.Unmarshal(raw[idx:], &chal); err != nil {
		return nil, err
	}
	out := &NTLMChallenge{TargetName: decodeNTLMString(chal.TargetName)}
	if chal.TargetInfo != nil {
		for _, av := range *chal.TargetInfo {
			switch av.AvID {
			case ntlmssp.MsvAvNbComputerName:
				out.NetBIOSComputer = decodeNTLMString(av.Value)
			case ntlmssp.MsvAvNbDomainName:
				out.NetBIOSDomain = decodeNTLMString(av.Value)
			case ntlmssp.MsvAvDnsComputerName:
				out.DNSComputer = decodeNTLMString(av.Value)
			case ntlmssp.MsvAvDnsDomainName:
				out.DNSDomain = decodeNTLMString(av.Value)
			case ntlmssp.MsvAvDnsTreeName:
				out.DNSTree = decodeNTLMString(av.Value)
			case ntlmssp.MsvAvTargetName:
				out.TargetSPN = decodeNTLMString(av.Value)
			case ntlmssp.MsvAvTimestamp:
				if len(av.Value) >= 8 {
					ts := binary.LittleEndian.Uint64(av.Value[:8])
					out.SystemTime = formatNTLMTimestamp(ts)
				}
			}
		}
	}
	if chal.Version != 0 {
		var v [8]byte
		binary.LittleEndian.PutUint64(v[:], chal.Version)
		major := v[0]
		minor := v[1]
		build := binary.LittleEndian.Uint16(v[2:4])
		rev := v[7]
		out.ProductVersion = fmt.Sprintf("%d.%d.%d ntlmrev %d", major, minor, build, rev)
	}
	return out, nil
}

func decodeNTLMString(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	if len(raw)%2 == 0 {
		u16 := make([]uint16, 0, len(raw)/2)
		for i := 0; i+1 < len(raw); i += 2 {
			c := binary.LittleEndian.Uint16(raw[i : i+2])
			if c == 0 {
				break
			}
			u16 = append(u16, c)
		}
		if len(u16) > 0 {
			runes := make([]rune, len(u16))
			for i, v := range u16 {
				runes[i] = rune(v)
			}
			return string(runes)
		}
	}
	return strings.TrimRight(string(raw), "\x00")
}

func formatNTLMTimestamp(fileTime uint64) string {
	const epochDiff = uint64(116444736000000000)
	if fileTime <= epochDiff {
		return ""
	}
	nanos := int64((fileTime - epochDiff) * 100)
	return time.Unix(0, nanos).UTC().Format(time.RFC3339)
}
