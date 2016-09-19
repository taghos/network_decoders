package network_decoders

import (
	"errors"
)


// Ethernet header.
// BUG(rnsanchez): missing fields.
type Ethernet struct {
	DstMAC		uint64
	SrcMAC		uint64

	EtherType	uint16
}


// Decodes raw bytes, assuming they represent an Ethernet frame.  In the case of
// too few bytes, complain.
func (eth *Ethernet) Decode(raw []byte) (err error) {
	if len(raw) < 14 {
		return errors.New("Short Ethernet frame")
	}

	eth.DstMAC = (uint64(raw[0]) << 40) + (uint64(raw[1]) << 32) + (uint64(raw[2]) << 24) +
		(uint64(raw[3]) << 16) + (uint64(raw[4]) << 8) + uint64(raw[5])
	eth.SrcMAC = (uint64(raw[6]) << 40) + (uint64(raw[7]) << 32) + (uint64(raw[8]) << 24) +
		(uint64(raw[9]) << 16) + (uint64(raw[10]) << 8) + uint64(raw[11])

	eth.EtherType = (uint16(raw[12]) << 8) + uint16(raw[13])

	return
}
