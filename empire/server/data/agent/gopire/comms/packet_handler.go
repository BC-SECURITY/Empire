package comms

/*

Packet handling functionality for Empire.

Defines packet types, builds tasking packets and parses result packets.

Packet format:

AES-256-GCM = AEAD encrypted with the shared staging key
AESc = AES encrypted using the client's session key
HMACc = first 16 bytes of a SHA256 HMAC using the client's session key

    Routing Packet:
    +------+---------------------------+--------------------------+
    |  IV  | AES-256-GCM(RoutingData)  | AESc(client packet data) | ...
    +------+---------------------------+--------------------------+
    |  12  |             32            |          length          |
    +------+---------------------------+--------------------------+

        AES-256-GCM(RoutingData):
        +------------------------+----------+
        |  AES-GCM(Encrypted)    | GCM Tag  |
        +------------------------+----------+
        |          16            |    16    |
        +------------------------+----------+

            RoutingData (plaintext):
            +-----------+------+------+-------+--------+
            | SessionID | Lang | Meta | Extra | Length |
            +-----------+------+------+-------+--------+
            |    8      |  1   |  1   |   2   |    4   |
            +-----------+------+------+-------+--------+

    SessionID = the sessionID that the packet is bound for
    Lang = indicates the language used
    Meta = indicates staging req/tasking req/result post/etc.
    Extra = reserved for future expansion


    AESc(client data)
    +--------+-----------------+-------+
    | AES IV | Enc Packet Data | HMACc |
    +--------+-----------------+-------+
    |   16   |   % 16 bytes    |  16   |
    +--------+-----------------+-------+

    Client data decrypted:
    +------+--------+--------------------+----------+---------+-----------+
    | Type | Length | total # of packets | packet # | task ID | task data |
    +------+--------+--------------------+--------------------+-----------+
    |  2   |   4    |         2          |    2     |    2    | <Length>  |
    +------+--------+--------------------+----------+---------+-----------+

    type = packet type
    total # of packets = number of total packets in the transmission
    Packet # = where the packet fits in the transmission
    Task ID = links the tasking to results for deconflict on server side


    Client *_SAVE packets have the sub format:

            [15 chars] - save prefix
            [5 chars]  - extension
            [X...]     - tasking data

*/

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
)

type PacketHandler struct {
	Server     string
	StagingKey []byte
	SessionID  string
	Aeskey     []byte
}

func (ph PacketHandler) BuildResponsePacket(taskingID int, packetData string, resultID int) []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint16(taskingID))
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint16(resultID))

	if packetData != "" {
		encodedData := base64.StdEncoding.EncodeToString([]byte(packetData))
		binary.Write(buf, binary.LittleEndian, uint32(len(encodedData)))
		buf.Write([]byte(encodedData))
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(0))
	}

	return buf.Bytes()
}

/*
"""

	Takes the specified parameters for a "routing packet" and builds/returns
	an AES-256-GCM encrypted routing packet.

	packet format:

	    Routing Packet:
	    +------+---------------------------+--------------------------+
	    |  IV  | AES-256-GCM(RoutingData)  | AESc(client packet data) | ...
	    +------+---------------------------+--------------------------+
	    |  12  |             32            |          length          |
	    +------+---------------------------+--------------------------+

	        AES-256-GCM(RoutingData):
	        +------------------------+----------+
	        |  AES-GCM(Encrypted)    | GCM Tag  |
	        +------------------------+----------+
	        |          16            |    16    |
	        +------------------------+----------+

	            RoutingData (plaintext):
	            +-----------+------+------+-------+--------+
	            | SessionID | Lang | Meta | Extra | Length |
	            +-----------+------+------+-------+--------+
	            |    8      |  1   |  1   |   2   |    4   |
	            +-----------+------+------+-------+--------+
*/
func (ph PacketHandler) BuildRoutingPacket(stagingKey []byte, sessionID string, meta int, additional uint16, encData []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteString(sessionID)                                   // 8 bytes - SessionID
	binary.Write(buf, binary.LittleEndian, uint8(4))             // 1 byte - Lang
	binary.Write(buf, binary.LittleEndian, uint8(meta))          // 1 byte - Meta
	binary.Write(buf, binary.LittleEndian, uint16(additional))   // 2 bytes - Extra
	binary.Write(buf, binary.LittleEndian, uint32(len(encData))) // 4 bytes - Length
	data := buf.Bytes()

	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		fmt.Println("Error generating AES-GCM IV:", err)
		return nil
	}

	block, err := aes.NewCipher(stagingKey)
	if err != nil {
		fmt.Println("Error creating AES cipher:", err)
		return nil
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("Error creating AES-GCM:", err)
		return nil
	}

	aesgcmEncData := gcm.Seal(nil, iv, data, []byte{})

	packet := append(iv, aesgcmEncData...)
	packet = append(packet, encData...)

	return packet
}

/*
Decodes the AES-256-GCM "routing packet" and parses raw agent data into:

	{sessionID : (language, meta, additional, [encData]), ...}

Routing packet format:

	Routing Packet:
	+------+---------------------------+--------------------------+
	|  IV  | AES-256-GCM(RoutingData)  | AESc(client packet data) | ...
	+------+---------------------------+--------------------------+
	|  12  |             32            |          length          |
	+------+---------------------------+--------------------------+

	    AES-256-GCM(RoutingData):
	    +------------------------+----------+
	    |  AES-GCM(Encrypted)    | GCM Tag  |
	    +------------------------+----------+
	    |          16            |    16    |
	    +------------------------+----------+

	        RoutingData (plaintext):
	        +-----------+------+------+-------+--------+
	        | SessionID | Lang | Meta | Extra | Length |
	        +-----------+------+------+-------+--------+
	        |    8      |  1   |  1   |   2   |    4   |
	        +-----------+------+------+-------+--------+
*/
func (ph PacketHandler) ParseRoutingPacket(stagingKey []byte, data []byte) (map[string][]interface{}, error) {
	results := make(map[string][]interface{})
	offset := 0
	ivLength := 12
	aeadHeaderLength := ivLength + 32

	for len(data)-offset >= aeadHeaderLength {
		iv := data[offset : offset+ivLength]

		block, err := aes.NewCipher(stagingKey)
		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		routingPacket, err := gcm.Open(nil, iv, data[offset+ivLength:offset+aeadHeaderLength], []byte{})
		if err != nil {
			return nil, err
		}

		sessionID := string(routingPacket[:8])
		language := routingPacket[8]
		meta := routingPacket[9]
		additional := binary.LittleEndian.Uint16(routingPacket[10:12])
		length := binary.LittleEndian.Uint32(routingPacket[12:16])

		var encData []byte
		if length > 0 {
			end := offset + aeadHeaderLength + int(length)
			if end > len(data) {
				return nil, fmt.Errorf("routing packet length %d exceeds available data", length)
			}
			encData = data[offset+aeadHeaderLength : end]
		} else {
			encData = nil
		}

		results[sessionID] = []interface{}{language, meta, additional, encData}

		offset += aeadHeaderLength + int(length)
		if offset >= len(data) {
			break
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no valid routing packets found")
	}

	return results, nil
}

func (ph PacketHandler) ParseTaskPacket(data []byte, offset int) (uint16, uint16, uint16, uint16, uint32, []byte, []byte, error) {
	if len(data) < offset+12 {
		return 0, 0, 0, 0, 0, nil, nil, fmt.Errorf("data too short to parse")
	}

	packetType := binary.LittleEndian.Uint16(data[offset : offset+2])
	totalPacket := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
	packetNum := binary.LittleEndian.Uint16(data[offset+4 : offset+6])
	resultID := binary.LittleEndian.Uint16(data[offset+6 : offset+8])
	length := binary.LittleEndian.Uint32(data[offset+8 : offset+12])

	if len(data) < offset+12+int(length) {
		return 0, 0, 0, 0, 0, nil, nil, fmt.Errorf("data too short for specified length")
	}

	packetData := data[offset+12 : offset+12+int(length)]
	remainingData := data[offset+12+int(length):]

	return packetType, totalPacket, packetNum, resultID, length, packetData, remainingData, nil
}

func (ph PacketHandler) DecodeRoutingPacket(data []byte, stagingKey []byte, sessionID string) (encData []byte, err error) {
	packets, err := ph.ParseRoutingPacket(stagingKey, data)
	if err != nil {
		// fmt.Println("Error parsing routing packet:", err)
		return
	}

	for agentID, packet := range packets {
		if agentID == sessionID {
			// language := packet[0].(byte)
			// meta := packet[1].(byte)
			// additional := packet[2].(uint16)
			encData := packet[3].([]byte)

			// fmt.Printf("Language: %d, Meta: %d, Additional: %d\n", language, meta, additional)
			return encData, nil
		} else {
			// encodedData := base64.StdEncoding.EncodeToString(data)
			// fmt.Println("Queued data for other agents:", encodedData)
			return nil, nil
		}
	}
	return nil, nil
}
