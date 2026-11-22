package session

import (
	"encoding/binary"
	"os"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

var (
	_ N.FrontHeadroom  = (*Stream)(nil)
	_ N.ExtendedWriter = (*Stream)(nil)
)

// FrontHeadroom asks callers that copy into the stream through sing's
// buffered copy loop to leave room for the frame header in front of the
// payload, so WriteBuffer can frame the data in place.
func (s *Stream) FrontHeadroom() int {
	return headerOverHeadSize
}

// WriteBuffer writes one data frame from buffer and releases it. With enough
// headroom the header is written in front of the payload and the buffer goes
// to the connection as is, skipping the copy into a new frame buffer that
// Write makes. Without headroom, or for payloads larger than one frame, it
// falls back to the same path as Write.
func (s *Stream) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	select {
	case <-s.writeDeadline.Wait():
		return os.ErrDeadlineExceeded
	default:
	}
	if dieErr := s.dieErr.Load(); dieErr != nil {
		return *dieErr
	}
	dataLen := buffer.Len()
	if dataLen == 0 {
		return nil
	}
	if dataLen > maxFrameDataLen || buffer.Start() < headerOverHeadSize {
		_, err := s.sess.writeDataFrame(s.id, buffer.Bytes())
		return err
	}
	header := buffer.ExtendHeader(headerOverHeadSize)
	header[0] = cmdPSH
	binary.BigEndian.PutUint32(header[1:5], s.id)
	binary.BigEndian.PutUint16(header[5:7], uint16(dataLen))
	_, err := s.sess.writeConn(buffer.Bytes())
	return err
}
