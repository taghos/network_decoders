package network_decoders

import (
	"errors"
)


// A standard TCP header, followed by a number of convenience attributes.
type TCP struct {
	SrcPort		uint16
	DstPort		uint16
	SeqNumber	uint32
	AckNumber	uint32
	DataOffset	uint
	ReservedZeroes	uint

	// ECN Nonce
	NS		uint
	// Congestion Window Reduced
	CWR		uint
	// ECN Echo
	ECE		uint
	// Urgent pointer is important
	URG		uint
	// ACK is important
	ACK		uint
	// Push data to application
	PSH		uint
	// Reset connection
	RST		uint
	// Synchronize sequence numbers
	SYN		uint
	// Finished sending
	FIN		uint

	WindowSize	uint16
	Checksum	uint16
	UrgentPointer	uint16

	Options		[]byte
	OptionsLen	uint

	NOPCount	uint
	MSS		uint
	WindowScale	uint
	SACKPermitted	uint

	SACK		[]uint32

	Timestamp	uint32
	TimestampEcho	uint32

	HeaderLen	uint
}


// Decode the raw stream of bytes, assuming it contains a TCP header.  If the
// stream is too short, decoding stops and an error message is returned.
func (tcp *TCP) Decode(raw []byte, parseopt bool) (err error) {
	if len(raw) < 20 {
		return errors.New("Short TCP packet")
	}

	tcp.SrcPort = (uint16(raw[0]) << 8) + uint16(raw[1])
	tcp.DstPort = (uint16(raw[2]) << 8) + uint16(raw[3])

	tcp.SeqNumber = (uint32(raw[4]) << 24) + (uint32(raw[5]) << 16) + (uint32(raw[6]) << 8) + uint32(raw[7])
	tcp.AckNumber = (uint32(raw[8]) << 24) + (uint32(raw[9]) << 16) + (uint32(raw[10]) << 8) + uint32(raw[11])

	tcp.DataOffset = uint(raw[12]) >> 4
	tcp.ReservedZeroes = (uint(raw[12]) >> 1) & 0x7
	tcp.NS = uint(raw[12]) & 0x1

	tcp.CWR = uint(raw[13]) >> 7
	tcp.ECE = (uint(raw[13]) >> 6) & 0x1
	tcp.URG = (uint(raw[13]) >> 5) & 0x1
	tcp.ACK = (uint(raw[13]) >> 4) & 0x1
	tcp.PSH = (uint(raw[13]) >> 3) & 0x1
	tcp.RST = (uint(raw[13]) >> 2) & 0x1
	tcp.SYN = (uint(raw[13]) >> 1) & 0x1
	tcp.FIN = uint(raw[13]) & 0x1

	tcp.WindowSize = (uint16(raw[14]) << 8) + uint16(raw[15])
	tcp.Checksum = (uint16(raw[16]) << 8) + uint16(raw[17])
	tcp.UrgentPointer = (uint16(raw[18]) << 8) + uint16(raw[19])

	tcp.HeaderLen = tcp.DataOffset * 4

	if tcp.DataOffset >= 5 && tcp.DataOffset <= 15 {
		tcp.OptionsLen = tcp.HeaderLen - 20
		if parseopt && int(tcp.HeaderLen) <= len(raw) {
			tcp.Options = raw[20:tcp.HeaderLen]

			var s uint
			for s = 20; s < tcp.HeaderLen; {
				switch (raw[s]) {
				// End of list
				case 0:
					break
				// Padding
				case 1:
					tcp.NOPCount++
					s++
					continue
				// MSS: 32-bit
				case 2:
					s++
					if raw[s] != 4 {
						panic("Incorrect length for MSS")
					}
					s++
					tcp.MSS = (uint(raw[s]) << 8) + uint(raw[s + 1])
					s += 2
				// Window scale: 24-bit
				case 3:
					s++
					if (raw[s] != 3) {
						panic("Incorrect length for window scale")
					}
					s++
					tcp.WindowScale = uint(raw[s])
					s++
				// SACK Permitted: 16-bit
				case 4:
					s++
					if (raw[s] != 2) {
						panic("Incorrect length for SACKPermitted")
					}
					tcp.SACKPermitted = 1
					s++
				// SACKs 1..4x 32-bit
				case 5:
					s++
					v := int(raw[s])
					s++
					if (v - 2) % 8 != 0 {
						panic("Incorrect length for SACK list")
					}

					v = (v - 2) / 4
					tcp.SACK = make([]uint32, v, v)
					for iter := 0; iter < v; iter++ {
						tcp.SACK[iter] = (uint32(raw[s]) << 24) + (uint32(raw[s + 1]) << 16) +
							(uint32(raw[s + 2]) << 8) + uint32(raw[s + 3])
						s += 4
					}
				// Timestamps
				case 8:
					s++
					if raw[s] != 10 {
						panic("Expecting 10 after Timestamp option")
					}
					s++
					tcp.Timestamp = (uint32(raw[s]) << 24) + (uint32(raw[s + 1]) << 16) +
						(uint32(raw[s + 2]) << 8) + uint32(raw[s + 3])
					s += 4
					tcp.TimestampEcho = (uint32(raw[s]) << 24) + (uint32(raw[s + 1]) << 16) +
						(uint32(raw[s + 2]) << 8) + uint32(raw[s + 3])
					s += 4
				default:
					panic("Unhandled TCP option identifier")
				}
			}
		} else {
			tcp.Options = raw[20:len(raw)]
		}
	}

	return
}
