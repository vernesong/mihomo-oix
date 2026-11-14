package types

import (
	"bufio"
	"context"
	"errors"
	"net"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/quic-go"
)

var (
	ErrClientClosed       = errors.New("tuic: client closed")
	ErrTooManyOpenStreams = errors.New("tuic: too many open streams")

	// ClientClosed and TooManyOpenStreams retain the original API names.
	ClientClosed       = ErrClientClosed
	TooManyOpenStreams = ErrTooManyOpenStreams
)

type DialFunc func(ctx context.Context) (quicConn *quic.Conn, err error)

type Client interface {
	DialContext(ctx context.Context, metadata *C.Metadata) (net.Conn, error)
	ListenPacket(ctx context.Context, metadata *C.Metadata) (net.PacketConn, error)
	OpenStreams() int64
	LastVisited() time.Time
	SetLastVisited(last time.Time)
	Close()
}

type ServerHandler interface {
	AuthOk() bool
	HandleTimeout()
	HandleStream(conn *N.BufferedConn) (err error)
	HandleMessage(message []byte) (err error)
	HandleUniStream(reader *bufio.Reader) (err error)
}

type UdpRelayMode uint8

const (
	QUIC UdpRelayMode = iota
	NATIVE
)
