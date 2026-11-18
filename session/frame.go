package session

import (
	"encoding/binary"
)

const ( // cmds
	cmdWaste               = 0 // Paddings
	cmdSYN                 = 1 // stream open
	cmdPSH                 = 2 // data push
	cmdFIN                 = 3 // stream close, a.k.a EOF mark
	cmdSettings            = 4 // Settings (Client send to Server)
	cmdAlert               = 5 // Alert
	cmdUpdatePaddingScheme = 6 // update padding scheme
	// Since version 2
	cmdSYNACK         = 7  // Server reports to the client that the stream has been opened
	cmdHeartRequest   = 8  // Keep alive command
	cmdHeartResponse  = 9  // Keep alive command
	cmdServerSettings = 10 // Settings (Server send to client)
	// cmdStats carries the server's view of the connection to the client. It
	// is a fork extension: a server only sends it to a client that asked with
	// "stats=1" in its settings, so a peer that does not know it never sees it.
	cmdStats = 11
	// cmdDNSRequest carries a DNS message from a client and cmdDNSResponse the
	// server's answer, matched by the request id in the stream id field. They
	// are a fork extension: a client only sends a request to a server that
	// offered "dns=1" in its settings, and a server only answers requests, so
	// a peer that does not know them never sees them.
	cmdDNSRequest  = 12
	cmdDNSResponse = 13
	// cmdProbeRequest starts or stops a throughput probe, cmdProbeData carries
	// its filler in either direction, and cmdProbeStatus is the server's
	// answer, all matched by the probe id in the stream id field. They are a
	// fork extension: a client only sends a request to a server that offered
	// "probe=1" in its settings, so a peer that does not know them never sees
	// them.
	cmdProbeRequest = 14
	cmdProbeData    = 15
	cmdProbeStatus  = 16
)

const (
	headerOverHeadSize = 1 + 4 + 2
)

// frame defines a packet from or to be multiplexed into a single connection
type frame struct {
	cmd  byte   // 1
	sid  uint32 // 4
	data []byte // 2 + len(data)
}

func newFrame(cmd byte, sid uint32) frame {
	return frame{cmd: cmd, sid: sid}
}

type rawHeader [headerOverHeadSize]byte

func (h rawHeader) Cmd() byte {
	return h[0]
}

func (h rawHeader) StreamID() uint32 {
	return binary.BigEndian.Uint32(h[1:])
}

func (h rawHeader) Length() uint16 {
	return binary.BigEndian.Uint16(h[5:])
}
