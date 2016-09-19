package network_decoders

import (
	"errors"
)


// A standard UDP header.
type UDP struct {
	SrcPort		uint16
	DstPort		uint16
	Length		uint16
	Checksum	uint16
}


// Decodes the raw stream of bytes into a UDP header.  If it is too short, raw
// is not decoded, and an error string is returned.
func (udp *UDP) Decode(raw []byte) (err error) {
	if len(raw) < 8 {
		return errors.New("Short UDP packet")
	}

	udp.SrcPort = (uint16(raw[0]) << 8) + uint16(raw[1])
	udp.DstPort = (uint16(raw[2]) << 8) + uint16(raw[3])

	udp.Length = (uint16(raw[4]) << 8) + uint16(raw[5])
	udp.Checksum = (uint16(raw[6]) << 8) + uint16(raw[7])

	return
}
