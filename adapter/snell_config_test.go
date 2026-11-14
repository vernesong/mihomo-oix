package adapter

import (
	"encoding/json"
	"maps"
	"reflect"
	"testing"

	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
)

func TestSnellAndHollowProtocolNames(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		kind    string
		mode    any
		ech     bool
		version int
		want    C.AdapterType
		invalid bool
	}{
		{name: "ordinary snell", kind: "snell", version: 3, want: C.Snell},
		{name: "legacy ech", kind: "snell", mode: "ech-tls", ech: true, version: 4, want: C.Hollow},
		{name: "legacy v6", kind: "snell", mode: "ech-tls", ech: true, version: 6, want: C.Hollow},
		{name: "hollow explicit mode", kind: "hollow", mode: "ech-tls", ech: true, version: 4, want: C.Hollow},
		{name: "hollow implicit mode", kind: "hollow", ech: true, version: 4, want: C.Hollow},
		{name: "hollow default version", kind: "hollow", ech: true, want: C.Hollow},
		{name: "hollow v6", kind: "hollow", ech: true, version: 6, want: C.Hollow},
		{name: "hollow cannot disable ech", kind: "hollow", mode: "http", ech: true, invalid: true},
		{name: "hollow invalid mode", kind: "hollow", mode: 1, ech: true, invalid: true},
		{name: "hollow requires ech config", kind: "hollow", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := map[string]any{}
			if tc.mode != nil {
				opts["mode"] = tc.mode
			}
			if tc.ech {
				opts["ech-config"] = echConfig
			}
			before := maps.Clone(opts)
			proxy, err := ParseProxy(map[string]any{
				"name": "fixture", "type": tc.kind, "server": "origin.example.com",
				"port": 443, "psk": "fixture-password", "version": tc.version, "obfs-opts": opts,
			})
			if !reflect.DeepEqual(before, opts) {
				t.Fatal("parsing mutated the input configuration")
			}
			if tc.invalid {
				if err == nil {
					proxy.Close()
					t.Fatal("accepted an invalid Hollow configuration")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			if proxy.Type() != tc.want {
				t.Fatalf("type = %v, want %v", proxy.Type(), tc.want)
			}
			data, err := proxy.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			var result struct {
				Type string `json:"type"`
			}
			if err = json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
			if result.Type != tc.want.String() {
				t.Fatalf("API type = %q, want %q", result.Type, tc.want.String())
			}
		})
	}
}
