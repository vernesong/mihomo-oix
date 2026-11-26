package cidr

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

func TestReadIpCidrSetRejectsUntrustedLength(t *testing.T) {
	data := binary.BigEndian.AppendUint64([]byte{1}, math.MaxInt64)
	if _, err := ReadIpCidrSet(bytes.NewReader(data)); err == nil {
		t.Fatal("accepted truncated oversized range list")
	}
}

func TestIpCidrSetBinaryRoundTrip(t *testing.T) {
	set := NewIpCidrSet()
	for _, prefix := range []string{"192.0.2.0/24", "2001:db8::/32"} {
		if err := set.AddIpCidrForString(prefix); err != nil {
			t.Fatal(err)
		}
	}
	if err := set.Merge(); err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := set.WriteBin(&wire); err != nil {
		t.Fatal(err)
	}
	restored, err := ReadIpCidrSet(&wire)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"192.0.2.8", "2001:db8::1"} {
		if !restored.IsContainForString(address) {
			t.Fatalf("lost range for %s", address)
		}
	}
}
