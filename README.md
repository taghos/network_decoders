# network decoders

A collection of network decoders for implementing network analyzers.  Raw data
is assumed to be a network packet as seen on the wire (e.g., captured with
`tcpdump` or `pcap`).

There are very few restrictions and, thus, fewer validations.  A higher-level
analyzer would reason about possibly malformed packets, and take appropriate
measures.

See also:
* https://github.com/google/gopacket
* https://github.com/miekg/pcap
