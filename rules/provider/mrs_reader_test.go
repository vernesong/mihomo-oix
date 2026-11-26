package provider

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/klauspost/compress/zstd"
)

func TestMrsRejectsInvalidHeaderLengths(t *testing.T) {
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	for _, fields := range [][2]int64{{-1, 0}, {0, 0}, {1, math.MaxInt64}, {1, -1}} {
		data := append([]byte{}, MrsMagicBytes[:]...)
		data = append(data, P.Domain.Byte())
		data = binary.BigEndian.AppendUint64(data, uint64(fields[0]))
		data = binary.BigEndian.AppendUint64(data, uint64(fields[1]))
		if _, err := rulesMrsParse(encoder.EncodeAll(data, nil), NewDomainStrategy()); err == nil {
			t.Fatalf("accepted count/extra lengths %v", fields)
		}
	}
}

func TestMrsRoundTripAndChecksum(t *testing.T) {
	var wire bytes.Buffer
	if err := ConvertToMrs([]byte("example.com\n+.example.net\n"), P.Domain, P.TextRule, &wire); err != nil {
		t.Fatal(err)
	}
	strategy, err := rulesMrsParse(wire.Bytes(), NewDomainStrategy())
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"example.com", "example.net", "www.example.net"} {
		if !strategy.Match(&C.Metadata{Host: host}, C.RuleMatchHelper{}) {
			t.Fatalf("lost domain %s", host)
		}
	}
	corrupt := bytes.Clone(wire.Bytes())
	corrupt[len(corrupt)-1] ^= 1
	if _, err := rulesMrsParse(corrupt, NewDomainStrategy()); err == nil {
		t.Fatal("accepted corrupted checksum")
	}
}
