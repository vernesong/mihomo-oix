package snell

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"testing"

	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
	"github.com/metacubex/mihomo/transport/snell/internal/v6shape"
)

type v6Vector struct {
	PSK         string
	Salt        []byte
	Payloads    [][]byte
	Wire        []byte
	LargeSHA256 string
	Generator   uint32
	Mix         uint32
}

func v6Vectors(t *testing.T) []v6Vector {
	t.Helper()
	data, err := os.ReadFile("testdata/v6-default-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []v6Vector
	if err = json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

// The expected bytes are emitted by the pinned upstream implementation, not by
// this codec. They cover all padding generators, all mixing modes, salt masking,
// prefix/padding AD, a padded zero record, and the subsequent reusable stream.
func TestV6UpstreamVectors(t *testing.T) {
	generators, mixes := map[uint32]bool{}, map[uint32]bool{}
	for _, v := range v6Vectors(t) {
		generators[v.Generator], mixes[v.Mix] = true, true
		t.Run(v.PSK, func(t *testing.T) {
			cipher := []byte(v.PSK)
			aead, err := v4AEAD(cipher, v.Salt)
			if err != nil {
				t.Fatal(err)
			}
			var wire bytes.Buffer
			w := &v6RecordWriter{w: &wire, aead: aead, profile: v6shape.NewProfile([]byte(v.PSK)), salt: v.Salt}
			for _, p := range v.Payloads {
				if err := w.writeRecord(p); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(wire.Bytes(), v.Wire) {
				t.Fatal("v6 wire differs from upstream")
			}
			source := bytes.NewReader(v.Wire)
			r := &v6RecordReader{r: source, cipher: cipher, profile: w.profile}
			for i, want := range v.Payloads {
				got, err := r.readRecord()
				if len(want) == 0 {
					if !errors.Is(err, shadowaead.ErrZeroChunk) {
						t.Fatalf("record %d boundary: %v", i, err)
					}
				} else if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("record %d decode: %v", i, err)
				}
				r.release()
			}
			if source.Len() != 0 {
				t.Fatalf("%d unread wire bytes", source.Len())
			}
			wire.Reset()
			w = &v6RecordWriter{w: &wire, aead: aead, profile: w.profile, salt: v.Salt}
			if _, err = w.Write(bytes.Repeat([]byte{0x5a}, 128*1024)); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(wire.Bytes())
			if hex.EncodeToString(sum[:]) != v.LargeSHA256 {
				t.Fatal("dynamic chunks differ from upstream")
			}
		})
	}
	if len(generators) != 4 || len(mixes) != 3 {
		t.Fatalf("fixture coverage: %d generators, %d mixers", len(generators), len(mixes))
	}
}

type v6DeadlineReader struct {
	data   []byte
	offset int
	fired  bool
}

func (r *v6DeadlineReader) Read(p []byte) (int, error) {
	if !r.fired && r.offset <= len(p) {
		n := copy(p, r.data[:r.offset])
		r.data = r.data[n:]
		r.fired = true
		return n, os.ErrDeadlineExceeded
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	r.offset -= n
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

func TestV6ReadResumesAtEveryWireOffset(t *testing.T) {
	v := v6Vectors(t)[0]
	for offset := 0; offset < len(v.Wire); offset++ {
		r := &v6RecordReader{r: &v6DeadlineReader{data: v.Wire, offset: offset}, cipher: []byte(v.PSK), profile: v6shape.NewProfile([]byte(v.PSK))}
		for i, want := range v.Payloads {
			got, err := r.readRecord()
			if errors.Is(err, os.ErrDeadlineExceeded) {
				got, err = r.readRecord()
			}
			if len(want) == 0 {
				if !errors.Is(err, shadowaead.ErrZeroChunk) {
					t.Fatalf("offset %d record %d: %v", offset, i, err)
				}
			} else if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("offset %d record %d: %v", offset, i, err)
			}
			r.release()
		}
	}
}

func TestV6RejectsCorruptionAndTruncation(t *testing.T) {
	v := v6Vectors(t)[0]
	prefix := v6shape.NewProfile([]byte(v.PSK)).SaltBlockLen()
	for _, offset := range []int{prefix, len(v.Wire) - 1, len(v.Wire)} {
		wire := append([]byte(nil), v.Wire...)
		if offset == len(wire) {
			wire = wire[:len(wire)-1]
		} else {
			wire[offset] ^= 0x80
		}
		r := &v6RecordReader{r: bytes.NewReader(wire), cipher: []byte(v.PSK), profile: v6shape.NewProfile([]byte(v.PSK))}
		var err error
		rejected := false
		for range v.Payloads {
			_, err = r.readRecord()
			r.release()
			if err != nil && !errors.Is(err, shadowaead.ErrZeroChunk) {
				rejected = true
				break
			}
		}
		if !rejected {
			t.Fatalf("corruption/truncation %d accepted", offset)
		}
		if _, again := r.readRecord(); again != err {
			t.Fatalf("fatal error not retained: %v, %v", err, again)
		}
	}
}

func TestV6BufferedRead(t *testing.T) {
	v := v6Vectors(t)[0]
	for _, size := range []int{1, 31, maxLength} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			r := &v6RecordReader{r: bytes.NewReader(v.Wire), cipher: []byte(v.PSK), profile: v6shape.NewProfile([]byte(v.PSK))}
			defer r.release()
			buf := make([]byte, size)
			for _, want := range v.Payloads {
				if len(want) == 0 {
					if n, err := r.Read(buf); n != 0 || !errors.Is(err, shadowaead.ErrZeroChunk) {
						t.Fatalf("stream boundary: n=%d, err=%v", n, err)
					}
					continue
				}
				for offset := 0; offset < len(want); {
					n, err := r.Read(buf[:min(len(buf), len(want)-offset)])
					if err != nil || n == 0 || !bytes.Equal(buf[:n], want[offset:offset+n]) {
						t.Fatalf("buffered payload at %d: n=%d, err=%v", offset, n, err)
					}
					offset += n
				}
			}
			if n, err := r.Read(buf); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("end of input: n=%d, err=%v", n, err)
			}
		})
	}
}
