// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package views

import (
	jsonv1 "encoding/json"
	"fmt"
	"github.com/metacubex/tailscale/util/go120/slices"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	qt "github.com/frankban/quicktest"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	jsonv2 "github.com/metacubex/jsonv2"
	"github.com/metacubex/tailscale/types/structs"
)

// Statically verify that each type implements the following interfaces.
var _ = []interface {
	jsonv1.Marshaler
	jsonv1.Unmarshaler
	jsonv2.MarshalerTo
	jsonv2.UnmarshalerFrom
}{
	(*ByteSlice[[]byte])(nil),
	(*SliceView[*testStruct, testStructView])(nil),
	(*Slice[testStruct])(nil),
	(*MapSlice[*testStruct, testStructView])(nil),
	(*Map[*testStruct, testStructView])(nil),
	(*ValuePointer[testStruct])(nil),
}

type viewStruct struct {
	Int        int
	Addrs      Slice[netip.Prefix]
	Strings    Slice[string]
	AddrsPtr   *Slice[netip.Prefix] `json:",omitempty"`
	StringsPtr *Slice[string]       `json:",omitempty"`
}

type noPtrStruct struct {
	Int int
	Str string
}

type withPtrStruct struct {
	Int    int
	StrPtr *string
}

func BenchmarkSliceIteration(b *testing.B) {
	var data []viewStruct
	for i := 0; i < 10000; i++ {
		data = append(data, viewStruct{Int: i})
	}
	b.ResetTimer()
	b.Run("Len", func(b *testing.B) {
		b.ReportAllocs()
		dv := SliceOf(data)
		for it := 0; it < b.N; it++ {
			sum := 0
			for i := 0; i < dv.Len(); i++ {
				sum += dv.At(i).Int
			}
		}
	})
	b.Run("Cached-Len", func(b *testing.B) {
		b.ReportAllocs()
		dv := SliceOf(data)
		for it := 0; it < b.N; it++ {
			sum := 0
			for i, n := 0, dv.Len(); i < n; i++ {
				sum += dv.At(i).Int
			}
		}
	})
	b.Run("direct", func(b *testing.B) {
		b.ReportAllocs()
		for it := 0; it < b.N; it++ {
			sum := 0
			for _, d := range data {
				sum += d.Int
			}
		}
	})
}

func TestViewsJSON(t *testing.T) {
	mustCIDR := func(cidrs ...string) (out []netip.Prefix) {
		for _, cidr := range cidrs {
			out = append(out, netip.MustParsePrefix(cidr))
		}
		return
	}
	ipp := SliceOf(mustCIDR("192.168.0.0/24"))
	ss := SliceOf([]string{"bar"})
	tests := []struct {
		name       string
		in         viewStruct
		wantJSONv1 string
		wantJSONv2 string
	}{
		{
			name:       "empty",
			in:         viewStruct{},
			wantJSONv1: `{"Int":0,"Addrs":null,"Strings":null}`,
			wantJSONv2: `{"Int":0,"Addrs":[],"Strings":[]}`,
		},
		{
			name: "everything",
			in: viewStruct{
				Int:        1234,
				Addrs:      ipp,
				AddrsPtr:   &ipp,
				StringsPtr: &ss,
				Strings:    ss,
			},
			wantJSONv1: `{"Int":1234,"Addrs":["192.168.0.0/24"],"Strings":["bar"],"AddrsPtr":["192.168.0.0/24"],"StringsPtr":["bar"]}`,
			wantJSONv2: `{"Int":1234,"Addrs":["192.168.0.0/24"],"Strings":["bar"],"AddrsPtr":["192.168.0.0/24"],"StringsPtr":["bar"]}`,
		},
	}

	for _, tc := range tests {
		cmpOpts := cmp.Options{
			cmp.AllowUnexported(Slice[string]{}),
			cmp.AllowUnexported(Slice[netip.Prefix]{}),
			cmpopts.EquateComparable(netip.Prefix{}),
		}
		t.Run("JSONv1", func(t *testing.T) {
			gotJSON, err := jsonv1.Marshal(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if string(gotJSON) != tc.wantJSONv1 {
				t.Fatalf("JSON: %s; want: %s", gotJSON, tc.wantJSONv1)
			}
			var got viewStruct
			if err := jsonv1.Unmarshal(gotJSON, &got); err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(got, tc.in, cmpOpts); d != "" {
				t.Fatalf("unmarshal mismatch (-got +want):\n%s", d)
			}
		})
		t.Run("JSONv2", func(t *testing.T) {
			gotJSON, err := jsonv2.Marshal(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if string(gotJSON) != tc.wantJSONv2 {
				t.Fatalf("JSON: %s; want: %s", gotJSON, tc.wantJSONv2)
			}
			var got viewStruct
			if err := jsonv2.Unmarshal(gotJSON, &got); err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(got, tc.in, cmpOpts, cmpopts.EquateEmpty()); d != "" {
				t.Fatalf("unmarshal mismatch (-got +want):\n%s", d)
			}
		})
	}
}

func TestViewUtils(t *testing.T) {
	v := SliceOf([]string{"foo", "bar"})
	c := qt.New(t)

	c.Check(v.ContainsFunc(func(s string) bool { return strings.HasPrefix(s, "f") }), qt.Equals, true)
	c.Check(v.ContainsFunc(func(s string) bool { return strings.HasPrefix(s, "g") }), qt.Equals, false)
	c.Check(v.IndexFunc(func(s string) bool { return strings.HasPrefix(s, "b") }), qt.Equals, 1)
	c.Check(v.IndexFunc(func(s string) bool { return strings.HasPrefix(s, "z") }), qt.Equals, -1)
	c.Check(SliceContains(v, "bar"), qt.Equals, true)
	c.Check(SliceContains(v, "baz"), qt.Equals, false)
	c.Check(SliceEqualAnyOrder(v, v), qt.Equals, true)
	c.Check(SliceEqualAnyOrder(v, SliceOf([]string{"bar", "foo"})), qt.Equals, true)
	c.Check(SliceEqualAnyOrder(v, SliceOf([]string{"foo"})), qt.Equals, false)
	c.Check(SliceEqualAnyOrder(SliceOf([]string{"a", "a", "b"}), SliceOf([]string{"a", "b", "b"})), qt.Equals, false)

	c.Check(SliceEqualAnyOrder(
		SliceOf([]string{"a", "b", "c"}).SliceFrom(1),
		SliceOf([]string{"b", "c"})),
		qt.Equals, true)
	c.Check(SliceEqualAnyOrder(
		SliceOf([]string{"a", "b", "c"}).Slice(1, 2),
		SliceOf([]string{"b", "c"}).SliceTo(1)),
		qt.Equals, true)
}

func TestSliceEqualAnyOrderFunc(t *testing.T) {
	type nc struct {
		_ structs.Incomparable
		v string
	}

	// ncFrom returns a Slice[nc] from a slice of []string
	ncFrom := func(s ...string) Slice[nc] {
		var out []nc
		for _, v := range s {
			out = append(out, nc{v: v})
		}
		return SliceOf(out)
	}

	// cmp returns a comparable value for a nc
	cmp := func(a nc) string { return a.v }

	v := ncFrom("foo", "bar")
	c := qt.New(t)

	// Simple case of slice equal to itself.
	c.Check(SliceEqualAnyOrderFunc(v, v, cmp), qt.Equals, true)

	// Different order.
	c.Check(SliceEqualAnyOrderFunc(v, ncFrom("bar", "foo"), cmp), qt.Equals, true)

	// Different values, same length
	c.Check(SliceEqualAnyOrderFunc(v, ncFrom("foo", "baz"), cmp), qt.Equals, false)

	// Different values, different length
	c.Check(SliceEqualAnyOrderFunc(v, ncFrom("foo"), cmp), qt.Equals, false)

	// Nothing shared
	c.Check(SliceEqualAnyOrderFunc(v, ncFrom("baz", "qux"), cmp), qt.Equals, false)

	// Long slice that matches
	longSlice := ncFrom("a", "b", "c", "d", "e", "f", "g", "h", "i", "j")
	longSame := ncFrom("b", "a", "c", "d", "e", "f", "g", "h", "i", "j") // first 2 elems swapped
	c.Check(SliceEqualAnyOrderFunc(longSlice, longSame, cmp), qt.Equals, true)

	// Long difference; past the quadratic limit
	longDiff := ncFrom("b", "a", "c", "d", "e", "f", "g", "h", "i", "k") // differs at end
	c.Check(SliceEqualAnyOrderFunc(longSlice, longDiff, cmp), qt.Equals, false)

	// The short slice optimization had a bug where it wouldn't handle
	// duplicate elements; test various cases here driven by code coverage.
	shortTestCases := []struct {
		name   string
		s1, s2 Slice[nc]
		want   bool
	}{
		{
			name: "duplicates_same_length",
			s1:   ncFrom("a", "a", "b"),
			s2:   ncFrom("a", "b", "b"),
			want: false,
		},
		{
			name: "duplicates_different_matched",
			s1:   ncFrom("x", "y", "a", "a", "b"),
			s2:   ncFrom("x", "y", "b", "a", "a"),
			want: true,
		},
		{
			name: "item_in_a_not_b",
			s1:   ncFrom("x", "y", "a", "b", "c"),
			s2:   ncFrom("x", "y", "b", "c", "q"),
			want: false,
		},
	}
	for _, tc := range shortTestCases {
		t.Run("short_"+tc.name, func(t *testing.T) {
			c.Check(SliceEqualAnyOrderFunc(tc.s1, tc.s2, cmp), qt.Equals, tc.want)
		})
	}
}

func TestSliceEqualAnyOrderAllocs(t *testing.T) {
	ss := func(s ...string) Slice[string] { return SliceOf(s) }
	cmp := func(s string) string { return s }

	t.Run("no-allocs-short-unordered", func(t *testing.T) {
		// No allocations for short comparisons
		short1 := ss("a", "b", "c")
		short2 := ss("c", "b", "a")
		if n := testing.AllocsPerRun(1000, func() {
			if !SliceEqualAnyOrder(short1, short2) {
				t.Fatal("not equal")
			}
			if !SliceEqualAnyOrderFunc(short1, short2, cmp) {
				t.Fatal("not equal")
			}
		}); n > 0 {
			t.Fatalf("allocs = %v; want 0", n)
		}
	})

	t.Run("no-allocs-long-match", func(t *testing.T) {
		long1 := ss("a", "b", "c", "d", "e", "f", "g", "h", "i", "j")
		long2 := ss("a", "b", "c", "d", "e", "f", "g", "h", "i", "j")

		if n := testing.AllocsPerRun(1000, func() {
			if !SliceEqualAnyOrder(long1, long2) {
				t.Fatal("not equal")
			}
			if !SliceEqualAnyOrderFunc(long1, long2, cmp) {
				t.Fatal("not equal")
			}
		}); n > 0 {
			t.Fatalf("allocs = %v; want 0", n)
		}
	})

	t.Run("allocs-long-unordered", func(t *testing.T) {
		// We do unfortunately allocate for long comparisons.
		long1 := ss("a", "b", "c", "d", "e", "f", "g", "h", "i", "j")
		long2 := ss("c", "b", "a", "e", "d", "f", "g", "h", "i", "j")

		if n := testing.AllocsPerRun(1000, func() {
			if !SliceEqualAnyOrder(long1, long2) {
				t.Fatal("not equal")
			}
			if !SliceEqualAnyOrderFunc(long1, long2, cmp) {
				t.Fatal("not equal")
			}
		}); n == 0 {
			t.Fatalf("unexpectedly didn't allocate")
		}
	})
}

func BenchmarkSliceEqualAnyOrder(b *testing.B) {
	b.Run("short", func(b *testing.B) {
		b.ReportAllocs()
		s1 := SliceOf([]string{"foo", "bar"})
		s2 := SliceOf([]string{"bar", "foo"})
		for i := 0; i < b.N; i++ {
			if !SliceEqualAnyOrder(s1, s2) {
				b.Fatal()
			}
		}
	})
	b.Run("long", func(b *testing.B) {
		b.ReportAllocs()
		s1 := SliceOf([]string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"})
		s2 := SliceOf([]string{"c", "b", "a", "e", "d", "f", "g", "h", "i", "j"})
		for i := 0; i < b.N; i++ {
			if !SliceEqualAnyOrder(s1, s2) {
				b.Fatal()
			}
		}
	})
}

func TestSliceEqual(t *testing.T) {
	a := SliceOf([]string{"foo", "bar"})
	b := SliceOf([]string{"foo", "bar"})
	if !SliceEqual(a, b) {
		t.Errorf("got a != b")
	}
	if !SliceEqual(a.SliceTo(0), b.SliceTo(0)) {
		t.Errorf("got a[:0] != b[:0]")
	}
	if SliceEqual(a.SliceTo(2), a.SliceTo(1)) {
		t.Error("got a[:2] == a[:1]")
	}
}

// TestSliceMapKey tests that the MapKey method returns the same key for slices
// with the same underlying slice and different keys for different slices or
// with same underlying slice but different bounds.
func TestSliceMapKey(t *testing.T) {
	underlying := []string{"foo", "bar"}
	nilSlice := SliceOf[string](nil)
	empty := SliceOf([]string{})
	u1 := SliceOf(underlying)
	u2 := SliceOf(underlying)
	u3 := SliceOf([]string{"foo", "bar"}) // different underlying slice

	sub1 := u1.Slice(0, 1)
	sub2 := u1.Slice(1, 2)
	sub3 := u1.Slice(0, 2)

	wantSame := []Slice[string]{u1, u2, sub3}
	for i := 1; i < len(wantSame); i++ {
		s0, si := wantSame[0], wantSame[i]
		k0 := s0.MapKey()
		ki := si.MapKey()
		if ki != k0 {
			t.Fatalf("wantSame[%d, %+v, %q) != wantSame[0, %+v, %q)", i, ki, si.AsSlice(), k0, s0.AsSlice())
		}
	}

	wantDiff := []Slice[string]{nilSlice, empty, sub1, sub2, sub3, u3}
	for i := 0; i < len(wantDiff); i++ {
		for j := i + 1; j < len(wantDiff); j++ {
			si, sj := wantDiff[i], wantDiff[j]
			ki, kj := wantDiff[i].MapKey(), wantDiff[j].MapKey()
			if ki == kj {
				t.Fatalf("wantDiff[%d, %+v, %q] == wantDiff[%d, %+v, %q] ", i, ki, si.AsSlice(), j, kj, sj.AsSlice())
			}
		}
	}
}

func TestContainsPointers(t *testing.T) {
	tests := []struct {
		name     string
		typ      reflect.Type
		wantPtrs bool
	}{
		{
			name:     "bool",
			typ:      reflect.TypeOf((*bool)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "int",
			typ:      reflect.TypeOf((*int)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "int8",
			typ:      reflect.TypeOf((*int8)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "int16",
			typ:      reflect.TypeOf((*int16)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "int32",
			typ:      reflect.TypeOf((*int32)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "int64",
			typ:      reflect.TypeOf((*int64)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "uint",
			typ:      reflect.TypeOf((*uint)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "uint8",
			typ:      reflect.TypeOf((*uint8)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "uint16",
			typ:      reflect.TypeOf((*uint16)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "uint32",
			typ:      reflect.TypeOf((*uint32)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "uint64",
			typ:      reflect.TypeOf((*uint64)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "uintptr",
			typ:      reflect.TypeOf((*uintptr)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "string",
			typ:      reflect.TypeOf((*string)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "float32",
			typ:      reflect.TypeOf((*float32)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "float64",
			typ:      reflect.TypeOf((*float64)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "complex64",
			typ:      reflect.TypeOf((*complex64)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "complex128",
			typ:      reflect.TypeOf((*complex128)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "netip-Addr",
			typ:      reflect.TypeOf((*netip.Addr)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "netip-Prefix",
			typ:      reflect.TypeOf((*netip.Prefix)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "netip-AddrPort",
			typ:      reflect.TypeOf((*netip.AddrPort)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "bool-ptr",
			typ:      reflect.TypeOf((**bool)(nil)).Elem(),
			wantPtrs: true,
		},
		{
			name:     "string-ptr",
			typ:      reflect.TypeOf((**string)(nil)).Elem(),
			wantPtrs: true,
		},
		{
			name:     "netip-Addr-ptr",
			typ:      reflect.TypeOf((**netip.Addr)(nil)).Elem(),
			wantPtrs: true,
		},
		{
			name:     "unsafe-ptr",
			typ:      reflect.TypeOf((*unsafe.Pointer)(nil)).Elem(),
			wantPtrs: true,
		},
		{
			name:     "no-ptr-struct",
			typ:      reflect.TypeOf((*noPtrStruct)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "ptr-struct",
			typ:      reflect.TypeOf((*withPtrStruct)(nil)).Elem(),
			wantPtrs: true,
		},
		{
			name:     "string-array",
			typ:      reflect.TypeOf((*[5]string)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "int-ptr-array",
			typ:      reflect.TypeOf((*[5]*int)(nil)).Elem(),
			wantPtrs: true,
		},
		{
			name:     "no-ptr-struct-array",
			typ:      reflect.TypeOf((*[5]noPtrStruct)(nil)).Elem(),
			wantPtrs: false,
		},
		{
			name:     "with-ptr-struct-array",
			typ:      reflect.TypeOf((*[5]withPtrStruct)(nil)).Elem(),
			wantPtrs: true,
		},
		{
			name:     "string-slice",
			typ:      reflect.TypeOf((*[]string)(nil)).Elem(),
			wantPtrs: true,
		},
		{
			name:     "int-ptr-slice",
			typ:      reflect.TypeOf((*[]int)(nil)).Elem(),
			wantPtrs: true,
		},
		{
			name:     "no-ptr-struct-slice",
			typ:      reflect.TypeOf((*[]noPtrStruct)(nil)).Elem(),
			wantPtrs: true,
		},
		{
			name:     "string-map",
			typ:      reflect.TypeOf((*map[string]string)(nil)).Elem(),
			wantPtrs: true,
		},
		{
			name:     "int-map",
			typ:      reflect.TypeOf((*map[int]int)(nil)).Elem(),
			wantPtrs: true,
		},
		{
			name:     "no-ptr-struct-map",
			typ:      reflect.TypeOf((*map[string]noPtrStruct)(nil)).Elem(),
			wantPtrs: true,
		},
		{
			name:     "chan",
			typ:      reflect.TypeOf((*chan int)(nil)).Elem(),
			wantPtrs: true,
		},
		{
			name:     "func",
			typ:      reflect.TypeOf((*func())(nil)).Elem(),
			wantPtrs: true,
		},
		{
			name:     "interface",
			typ:      reflect.TypeOf((*any)(nil)).Elem(),
			wantPtrs: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotPtrs := containsPointers(tt.typ); gotPtrs != tt.wantPtrs {
				t.Errorf("got %v; want %v", gotPtrs, tt.wantPtrs)
			}
		})
	}
}

func TestSliceRange(t *testing.T) {
	sv := SliceOf([]string{"foo", "bar"})
	var got []string
	sv.All()(func(i int, v string) bool {
		got = append(got, fmt.Sprintf("%d-%s", i, v))
		return true
	})
	want := []string{"0-foo", "1-bar"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

type testStruct struct{ value string }

func (p *testStruct) Clone() *testStruct {
	if p == nil {
		return p
	}
	return &testStruct{p.value}
}
func (p *testStruct) View() testStructView { return testStructView{p} }

type testStructView struct{ p *testStruct }

func (v testStructView) Valid() bool { return v.p != nil }
func (v testStructView) AsStruct() *testStruct {
	if v.p == nil {
		return nil
	}
	return v.p.Clone()
}
func (v testStructView) ValueForTest() string { return v.p.value }

func TestSliceViewRange(t *testing.T) {
	vs := SliceOfViews[*testStruct, testStructView]([]*testStruct{{value: "foo"}, {value: "bar"}})
	var got []string
	vs.All()(func(i int, v testStructView) bool {
		got = append(got, fmt.Sprintf("%d-%s", i, v.AsStruct().value))
		return true
	})
	want := []string{"0-foo", "1-bar"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestMapIter(t *testing.T) {
	m := MapOf(map[string]int{"foo": 1, "bar": 2})
	var got []string
	m.All()(func(k string, v int) bool {
		got = append(got, fmt.Sprintf("%s-%d", k, v))
		return true
	})
	slices.Sort(got)
	want := []string{"bar-2", "foo-1"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestMapSliceIter(t *testing.T) {
	m := MapSliceOf(map[string][]int{"foo": {3, 4}, "bar": {1, 2}})
	var got []string
	m.All()(func(k string, v Slice[int]) bool {
		got = append(got, fmt.Sprintf("%s-%d", k, v))
		return true
	})
	slices.Sort(got)
	want := []string{"bar-{[1 2]}", "foo-{[3 4]}"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestMapFnIter(t *testing.T) {
	m := MapFnOf[string, *testStruct, testStructView](map[string]*testStruct{
		"foo": {value: "fooVal"},
		"bar": {value: "barVal"},
	}, func(p *testStruct) testStructView { return testStructView{p} })
	var got []string
	m.All()(func(k string, v testStructView) bool {
		got = append(got, fmt.Sprintf("%v-%v", k, v.ValueForTest()))
		return true
	})
	slices.Sort(got)
	want := []string{"bar-barVal", "foo-fooVal"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestMapViewsEqual(t *testing.T) {
	testCases := []struct {
		name string
		a, b map[string]string
		want bool
	}{
		{
			name: "both_nil",
			a:    nil,
			b:    nil,
			want: true,
		},
		{
			name: "both_empty",
			a:    map[string]string{},
			b:    map[string]string{},
			want: true,
		},
		{
			name: "one_nil",
			a:    nil,
			b:    map[string]string{"a": "1"},
			want: false,
		},
		{
			name: "different_length",
			a:    map[string]string{"a": "1"},
			b:    map[string]string{"a": "1", "b": "2"},
			want: false,
		},
		{
			name: "different_values",
			a:    map[string]string{"a": "1"},
			b:    map[string]string{"a": "2"},
			want: false,
		},
		{
			name: "different_keys",
			a:    map[string]string{"a": "1"},
			b:    map[string]string{"b": "1"},
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := MapViewsEqual(MapOf(tc.a), MapOf(tc.b))
			if got != tc.want {
				t.Errorf("MapViewsEqual: got=%v, want %v", got, tc.want)
			}

			got = MapViewsEqualFunc(MapOf(tc.a), MapOf(tc.b), func(a, b string) bool {
				return a == b
			})
			if got != tc.want {
				t.Errorf("MapViewsEqualFunc: got=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestMapViewsEqualFunc(t *testing.T) {
	// Test that we can compare maps with two different non-comparable
	// values using a custom comparison function.
	type customStruct1 struct {
		_      structs.Incomparable
		Field1 string
	}
	type customStruct2 struct {
		_      structs.Incomparable
		Field2 string
	}

	a := map[string]customStruct1{"a": {Field1: "1"}}
	b := map[string]customStruct2{"a": {Field2: "1"}}

	got := MapViewsEqualFunc(MapOf(a), MapOf(b), func(a customStruct1, b customStruct2) bool {
		return a.Field1 == b.Field2
	})
	if !got {
		t.Errorf("MapViewsEqualFunc: got=%v, want true", got)
	}
}
