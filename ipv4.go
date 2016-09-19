package network_decoders

import (
	"errors"
)


// A standard IPv4 header, followed by convenience attributes.
type IPv4 struct {
	Version		uint16
	IHL		uint16
	DSCP		uint16
	ECN		uint16
	TotalLength	uint16
	Identification	uint16
	Flags		uint16
	FragmentOffset	uint16
	TTL		uint16
	Protocol	uint16
	Checksum	uint16
	SrcAddr		uint32
	DstAddr		uint32
	Options		[]byte

	// Length of the Options field.
	OptionsLen	uint
	// Length of the complete IPv4 header.
	HeaderLen	uint
}


// Decodes a raw stream of bytes into what is expected to be an IPv4 datagram.
// If the stream is shorter than the expected amount of bytes, the stream is not
// decoded and an error string is returned.
func (ipv4 *IPv4) Decode(raw []byte) (err error) {
	// Check whether it is minimally OK to decode as an IPv4 packet.
	var ihl uint = uint(raw[0]) & 0xF
	if int(ihl * 4) > len(raw) {
		return errors.New("IPv4 packet smaller than announced in IPv4.IHL")
	}

	ipv4.Version = uint16(raw[0] >> 4)
	ipv4.IHL = uint16(ihl)

	ipv4.DSCP = uint16(raw[1] >> 2)
	ipv4.ECN = uint16(raw[1] & 0x3)

	ipv4.TotalLength = (uint16(raw[2]) << 8) + uint16(raw[3])

	ipv4.Identification = (uint16(raw[4]) << 8) + uint16(raw[5])

	ipv4.Flags = uint16(raw[6] >> 5)
	ipv4.FragmentOffset = (uint16(raw[6] & 0x1F) << 8) + uint16(raw[7])

	ipv4.TTL = uint16(raw[8])
	ipv4.Protocol = uint16(raw[9])

	ipv4.Checksum = (uint16(raw[10]) << 8) + uint16(raw[11])

	ipv4.SrcAddr = (uint32(raw[12]) << 24) + (uint32(raw[13]) << 16) + (uint32(raw[14]) << 8) + uint32(raw[15])
	ipv4.DstAddr = (uint32(raw[16]) << 24) + (uint32(raw[17]) << 16) + (uint32(raw[18]) << 8) + uint32(raw[19])

	ipv4.OptionsLen = ihl * 4 - 20
	ipv4.HeaderLen = 20 + ipv4.OptionsLen

	if ipv4.OptionsLen > 0 {
		ipv4.Options = raw[20:ipv4.HeaderLen]
	}

	return
}
