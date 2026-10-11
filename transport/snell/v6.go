package snell

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
	"github.com/metacubex/mihomo/transport/snell/internal/v6shape"
)

var (
	errV6InvalidRecord  = errors.New("snell invalid encrypted data")
	errV6RecordTooLarge = errors.New("snell encrypted data too large")
)

const v6MaxWriteRecordSize = 20 * 1024

// v6Conn carries default-mode records inside exporter-authenticated ECH only.
type v6Conn struct {
	net.Conn
	psk, exporter   []byte
	profile         *v6shape.Profile
	r               *v6RecordReader
	w               *v6RecordWriter
	readMu, writeMu sync.Mutex
}

func newV6Conn(conn net.Conn, psk, exporter []byte) *v6Conn {
	return &v6Conn{Conn: conn, psk: append([]byte(nil), psk...), exporter: append([]byte(nil), exporter...), profile: v6shape.NewProfile(psk)}
}

func (c *v6Conn) initWriter() error {
	if c.w != nil {
		return c.w.err
	}
	nonce := make([]byte, v4SaltSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	tag, err := identityAuthTag(c.psk, c.exporter, nonce, identityWireMagicV6)
	if err != nil {
		return err
	}
	envelope := append(nonce, identityWireMagicV6...)
	envelope = append(envelope, IdentityV2HeaderFromPSK(c.psk)...)
	envelope = append(envelope, tag...)
	salt := make([]byte, v4SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	aead, err := v4AEAD(c.psk, salt)
	if err != nil {
		return err
	}
	c.w = &v6RecordWriter{w: c.Conn, aead: aead, profile: c.profile, salt: salt, pending: envelope}
	return nil
}

func (c *v6Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.r == nil {
		c.r = &v6RecordReader{r: c.Conn, cipher: c.psk, profile: c.profile}
	}
	return c.r.Read(b)
}

func (c *v6Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.initWriter(); err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, c.w.WritePacket(nil)
	}
	return c.w.Write(b)
}

func (c *v6Conn) WritePacketFrame(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(b) > maxLength {
		return 0, errV6RecordTooLarge
	}
	if err := c.initWriter(); err != nil {
		return 0, err
	}
	if err := c.w.WritePacket(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *v6Conn) Close() error {
	err := c.Conn.Close()
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.r != nil {
		c.r.release()
		c.r.pending = nil
		c.r.fatal = net.ErrClosed
	}
	return err
}

func writeV6All(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

// v6RecordReader retains each incomplete stage across a read deadline. Sniffing
// may time out in the salt, prefix, encrypted header, padding or payload; retrying
// must neither lose bytes nor advance the nonce twice.
type v6RecordReader struct {
	r                io.Reader
	cipher           []byte
	profile          *v6shape.Profile
	aead             cipher.AEAD
	nonce            [12]byte
	seq              uint64
	stage            byte
	pending          []byte
	got              int
	padding, payload int
	cached           []byte
	block            []byte
	fatal            error
}

func (r *v6RecordReader) fill(size int) error {
	if r.pending == nil {
		r.pending = make([]byte, size)
	}
	for r.got < size {
		n, err := r.r.Read(r.pending[r.got:])
		r.got += n
		if err != nil && r.got < size {
			if errors.Is(err, io.EOF) && (r.got > 0 || r.stage == 2) {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if n == 0 && err == nil {
			return io.ErrNoProgress
		}
	}
	r.got = 0
	return nil
}

func (r *v6RecordReader) readRecord() (payload []byte, err error) {
	if r.fatal != nil {
		return nil, r.fatal
	}
	defer func() {
		if err == nil || errors.Is(err, shadowaead.ErrZeroChunk) {
			return
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			return
		}
		r.fatal = err
		r.pending = nil
		r.release()
	}()
	if r.seq > uint64(^uint32(0)) {
		return nil, errV6InvalidRecord
	}
	seq := uint32(r.seq)
	if r.stage == 0 {
		if err = r.fill(r.profile.SaltBlockLen()); err != nil {
			return nil, err
		}
		salt := r.profile.DecodeSalt(r.pending)
		r.aead, err = v4AEAD(r.cipher, salt[:])
		if err != nil {
			return nil, err
		}
		r.pending = nil
		r.stage = 1
	}
	if r.stage == 1 {
		prefixLen := r.profile.PrefixLen(seq)
		if err = r.fill(prefixLen + v4HeaderPlainSize + 16); err != nil {
			return nil, err
		}
		prefix, sealed := r.pending[:prefixLen], r.pending[prefixLen:]
		header, openErr := r.aead.Open(sealed[:0], r.nonce[:], sealed, prefix)
		if openErr != nil {
			return nil, fmt.Errorf("snell encrypted data verification failed: %w", openErr)
		}
		incrementV4Nonce(r.nonce[:])
		// Retain dler's bounded record/datagram contract across v4/v6 and relays.
		if len(header) != v4HeaderPlainSize || header[0] != Version4 {
			return nil, errV6InvalidRecord
		}
		r.padding = int(binary.BigEndian.Uint16(header[3:5]))
		r.payload = int(binary.BigEndian.Uint16(header[5:7]))
		if r.payload > maxLength {
			return nil, errV6RecordTooLarge
		}
		r.pending = nil
		r.stage = 2
	}
	bodySize := r.padding
	if r.payload > 0 {
		bodySize += r.payload + 16
	}
	if r.pending == nil {
		r.block = pool.Get(bodySize)
		r.pending = r.block
	}
	if err = r.fill(bodySize); err != nil {
		return nil, err
	}
	r.stage = 1
	r.seq++
	body := r.pending
	r.pending = nil
	if r.payload == 0 {
		r.release()
		return nil, shadowaead.ErrZeroChunk
	}
	padding, sealed := body[:r.padding], body[r.padding:]
	r.profile.Mix(seq, padding, sealed)
	payload, err = r.aead.Open(sealed[:0], r.nonce[:], sealed, padding)
	if err != nil {
		return nil, fmt.Errorf("snell encrypted data verification failed: %w", err)
	}
	incrementV4Nonce(r.nonce[:])
	return payload, nil
}

func (r *v6RecordReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if len(r.cached) == 0 {
		var err error
		r.cached, err = r.readRecord()
		if err != nil {
			return 0, err
		}
	}
	n := copy(b, r.cached)
	r.cached = r.cached[n:]
	if len(r.cached) == 0 {
		r.release()
	}
	return n, nil
}

func (r *v6RecordReader) release() {
	_ = pool.Put(r.block)
	r.block, r.cached = nil, nil
}

type v6RecordWriter struct {
	w       io.Writer
	aead    cipher.AEAD
	profile *v6shape.Profile
	salt    []byte
	pending []byte
	nonce   [12]byte
	seq     uint64
	chunk   v6shape.ChunkState
	err     error
}

func (w *v6RecordWriter) writeRecord(payload []byte) error {
	if w.err != nil {
		return w.err
	}
	if w.seq > uint64(^uint32(0)) {
		w.err = errV6InvalidRecord
		return w.err
	}
	if len(payload) > maxLength {
		return errV6RecordTooLarge
	}
	seq := uint32(w.seq)
	first := w.salt != nil
	saltLen := 0
	if first {
		saltLen = w.profile.SaltBlockLen()
	}
	prefixLen := w.profile.PrefixLen(seq)
	paddingLen := w.profile.PaddingLen(seq, len(payload), first)
	payloadLen := len(payload)
	if payloadLen > 0 {
		payloadLen += 16
	}
	size := len(w.pending) + saltLen + prefixLen + v4HeaderPlainSize + 16 + paddingLen + payloadLen
	if size > v6MaxWriteRecordSize {
		w.err = errV6RecordTooLarge
		return w.err
	}
	out := pool.Get(size)
	defer pool.Put(out)
	offset := copy(out, w.pending)
	if first {
		w.profile.EncodeSalt(w.salt, out[offset:offset+saltLen])
		offset += saltLen
	}
	prefix := out[offset : offset+prefixLen]
	w.profile.Fill(seq, prefix)
	offset += prefixLen
	header := out[offset : offset+v4HeaderPlainSize+16]
	header[0], header[1], header[2] = Version4, 0, 0 // v6 retains the v4 inner header byte
	binary.BigEndian.PutUint16(header[3:5], uint16(paddingLen))
	binary.BigEndian.PutUint16(header[5:7], uint16(len(payload)))
	w.aead.Seal(header[:0], w.nonce[:], header[:v4HeaderPlainSize], prefix)
	incrementV4Nonce(w.nonce[:])
	offset += len(header)
	padding := out[offset : offset+paddingLen]
	w.profile.Fill(seq, padding)
	offset += paddingLen
	if len(payload) > 0 {
		sealed := w.aead.Seal(out[offset:offset], w.nonce[:], payload, padding)
		incrementV4Nonce(w.nonce[:])
		w.profile.Mix(seq, padding, sealed)
	}
	w.seq++
	w.salt, w.pending = nil, nil
	// Any failed or partial record write poisons this direction permanently.
	w.err = writeV6All(w.w, out)
	return w.err
}

func (w *v6RecordWriter) Write(p []byte) (int, error) {
	n := 0
	now := time.Now().Unix()
	for len(p) > 0 {
		limit := w.profile.PayloadLimit(uint32(w.seq), now, &w.chunk)
		size := min(len(p), limit, maxLength)
		if err := w.writeRecord(p[:size]); err != nil {
			return n, err
		}
		n += size
		p = p[size:]
	}
	return n, nil
}

func (w *v6RecordWriter) WritePacket(payload []byte) error {
	w.profile.PayloadLimit(uint32(w.seq), time.Now().Unix(), &w.chunk)
	return w.writeRecord(payload)
}
