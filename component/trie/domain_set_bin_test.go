package trie

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"testing"
)

func TestReadDomainSetRejectsUntrustedLengths(t *testing.T) {
	for _, prefix := range [][]byte{
		{1},
		binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64([]byte{1}, 1), 1),
	} {
		data := binary.BigEndian.AppendUint64(prefix, math.MaxInt64)
		if _, err := ReadDomainSetBin(bytes.NewReader(data)); err == nil {
			t.Fatal("accepted truncated oversized set")
		}
	}
}

func TestReadDomainSetRejectsMalformedStructure(t *testing.T) {
	for _, set := range []*DomainSet{
		{leaves: []uint64{2}, labelBitmap: []uint64{0}, labels: []byte{'a'}},
		{leaves: []uint64{2}, labelBitmap: []uint64{5}, labels: []byte{'a'}},
		{leaves: []uint64{4}, labelBitmap: []uint64{6}, labels: []byte{'a'}},
	} {
		var wire bytes.Buffer
		if err := set.WriteBin(&wire); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadDomainSetBin(&wire); err == nil {
			t.Fatal("accepted invalid succinct tree")
		}
	}
}

func FuzzReadDomainSetBin(f *testing.F) {
	var builder DomainSetBuilder
	_ = builder.Insert("+.example.com")
	_ = builder.Insert("example.net")
	var wire bytes.Buffer
	_ = builder.Build().WriteBin(&wire)
	f.Add(wire.Bytes())
	f.Add([]byte{1})
	f.Fuzz(func(t *testing.T, data []byte) {
		set, err := ReadDomainSetBin(bytes.NewReader(data))
		if err == nil {
			set.Has("example.com")
			set.Has("other.example.net")
			set.Foreach(func(string) bool { return true })
		}
	})
}

func TestReadDomainMapRejectsMismatchedValues(t *testing.T) {
	var builder DomainSetBuilder
	_ = builder.Insert("example.com")
	var wire bytes.Buffer
	if err := builder.Build().WriteBin(&wire); err != nil {
		t.Fatal(err)
	}
	wire.Write([]byte{0, 1})
	if err := binary.Write(&wire, binary.BigEndian, int64(math.MaxInt64)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDomainMapBin(&wire, func(r io.Reader) (byte, error) {
		var b [1]byte
		_, err := io.ReadFull(r, b[:])
		return b[0], err
	}); err == nil {
		t.Fatal("accepted mismatched value count")
	}
}
