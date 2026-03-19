package msrpc

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zmap/zgrab2/lib/smb/ntlmssp"
	smbencoder "github.com/zmap/zgrab2/lib/smb/smb/encoder"
)

var (
	//go:embed data/cpe.json
	windowsBuildVersionToCPEJSON []byte

	windowsBuildVersionToCPE     map[string][]string
	windowsBuildVersionToCPEErr  error
	windowsBuildVersionToCPEOnce sync.Once
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
		out.BuildVersion = fmt.Sprintf("%d.%d.%d", major, minor, build)
		out.NTLMRevision = rev
		out.WindowsFamily, out.CandidateCPEs = lookupWindowsVersionMetadata(major, minor, build)
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

func lookupWindowsVersionMetadata(major, minor uint8, build uint16) (string, []string) {
	if build == 0 {
		return "", nil
	}

	rawCandidates := getWindowsBuildCandidates(major, minor, build)
	if len(rawCandidates) == 0 {
		return "", nil
	}

	familyNames := make([]string, 0, len(rawCandidates))
	familyCPEs := make([]string, 0, len(rawCandidates))
	seenNames := make(map[string]struct{}, len(rawCandidates))
	seenCPEs := make(map[string]struct{}, len(rawCandidates))

	for _, cpe := range rawCandidates {
		familyName, familyCPE, ok := canonicalizeWindowsFamily(cpe)
		if !ok {
			continue
		}
		if _, exists := seenNames[familyName]; !exists {
			seenNames[familyName] = struct{}{}
			familyNames = append(familyNames, familyName)
		}
		if _, exists := seenCPEs[familyCPE]; !exists {
			seenCPEs[familyCPE] = struct{}{}
			familyCPEs = append(familyCPEs, familyCPE)
		}
	}

	sort.Strings(familyNames)
	sort.Strings(familyCPEs)

	return strings.Join(familyNames, " | "), familyCPEs
}

func getWindowsBuildCandidates(major, minor uint8, build uint16) []string {
	mappings, err := loadWindowsBuildVersionToCPE()
	if err != nil {
		return nil
	}

	keys := []string{
		fmt.Sprintf("%d.%d.%d", major, minor, build),
		strconv.FormatUint(uint64(build), 10),
	}

	candidates := make([]string, 0)
	seen := make(map[string]struct{})
	for _, key := range keys {
		values := mappings[key]
		for _, value := range values {
			if _, exists := seen[value]; exists {
				continue
			}
			seen[value] = struct{}{}
			candidates = append(candidates, value)
		}
	}

	return candidates
}

func loadWindowsBuildVersionToCPE() (map[string][]string, error) {
	windowsBuildVersionToCPEOnce.Do(func() {
		windowsBuildVersionToCPE = make(map[string][]string)
		windowsBuildVersionToCPEErr = json.Unmarshal(windowsBuildVersionToCPEJSON, &windowsBuildVersionToCPE)
	})

	return windowsBuildVersionToCPE, windowsBuildVersionToCPEErr
}

func canonicalizeWindowsFamily(cpe string) (string, string, bool) {
	parts := strings.Split(cpe, ":")
	if len(parts) < 6 || parts[0] != "cpe" || parts[2] != "o" || parts[3] != "microsoft" {
		return "", "", false
	}

	product := parts[4]
	version := parts[5]
	product, version = normalizeWindowsProductVersion(product, version)
	if product == "" {
		return "", "", false
	}

	familyVersion := version
	switch {
	case familyVersion == "", familyVersion == "-", familyVersion == "*":
		familyVersion = "*"
	case isExactBuildVersion(familyVersion):
		familyVersion = "*"
	}

	familyName := product
	if familyVersion != "*" {
		familyName = familyName + ":" + familyVersion
	}

	familyCPE := fmt.Sprintf("cpe:2.3:o:microsoft:%s:%s:*:*:*:*:*:*:*", product, familyVersion)
	return familyName, familyCPE, true
}

func normalizeWindowsProductVersion(product, version string) (string, string) {
	product = strings.ToLower(product)
	version = strings.ToLower(version)

	switch product {
	case "windows-nt":
		product = "windows_nt"
	case "windows-ce":
		product = "windows_ce"
	case "windows_8.0":
		product = "windows_8"
	case "windowst":
		if version == "vista" {
			product = "windows_vista"
			version = "*"
		}
	case "windows_10":
		if version != "" && version != "-" && version != "*" {
			product = "windows_10_" + version
			version = "*"
		}
	case "windows_11":
		if version != "" && version != "-" && version != "*" {
			product = "windows_11_" + version
			version = "*"
		}
	case "windows_server":
		switch version {
		case "2003", "2008", "2012", "2019", "2022", "2025":
			product = "windows_server_" + version
			version = "*"
		case "20h2":
			product = "windows_server_20h2"
			version = "*"
		case "1709", "1803", "1903", "1909", "2004":
			product = "windows_server_2016"
		}
	case "windows_server_1709":
		product, version = "windows_server_2016", "1709"
	case "windows_server_1803":
		product, version = "windows_server_2016", "1803"
	case "windows_server_1903":
		product, version = "windows_server_2016", "1903"
	case "windows_server_1909":
		product, version = "windows_server_2016", "1909"
	case "windows_server_2004":
		product, version = "windows_server_2016", "2004"
	case "windows_2003_server":
		product, version = "windows_server_2003", "*"
	case "windows-9x":
		switch version {
		case "95":
			product, version = "windows_95", "*"
		case "98":
			product, version = "windows_98", "*"
		case "98se":
			product, version = "windows_98se", "*"
		case "me":
			product, version = "windows_me", "*"
		}
	}

	return product, version
}

func isExactBuildVersion(version string) bool {
	if version == "" {
		return false
	}
	parts := strings.Split(version, ".")
	if len(parts) < 3 || len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return true
}
