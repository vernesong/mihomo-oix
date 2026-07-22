package oix

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestParamsEditableOptions(t *testing.T) {
	params := parseParams("&lv=2&type=love&tfo=false&simplerules=true&area=hk&custom=1")

	if params.Level != levelEmergency || params.Type != "love" {
		t.Fatalf("unexpected routing params: %+v", params)
	}
	if params.TFO == nil || *params.TFO {
		t.Fatalf("unexpected tfo: %+v", params.TFO)
	}
	if !params.SimpleRules {
		t.Fatal("simplerules was not parsed")
	}
	wantExtras := map[string]string{"area": "hk", "custom": "1"}
	if !reflect.DeepEqual(params.Extras, wantExtras) {
		t.Fatalf("extras = %#v, want %#v", params.Extras, wantExtras)
	}
	if got, want := params.encode(), "&lv=2&type=love&tfo=false&simplerules=true&area=hk&custom=1"; got != want {
		t.Fatalf("Encode() = %q, want %q", got, want)
	}
}

func TestParamsRoundTripEncoding(t *testing.T) {
	params := parseParams("&space=a%20b&plus=a+b&ampersand=a%26b")
	encoded := params.encode()

	if got := parseParams(encoded); !reflect.DeepEqual(got, params) {
		t.Fatalf("round trip = %#v, want %#v", got, params)
	}
	if strings.Contains(encoded, "%2520") {
		t.Fatalf("value was double encoded: %q", encoded)
	}
	if !strings.Contains(encoded, "ampersand=a%26b") {
		t.Fatalf("ampersand was not encoded: %q", encoded)
	}
}

func TestParamsRejectInvalidAndInternalKeys(t *testing.T) {
	params := parseParams("&lv=bad&LV=bad&type=love&type&tfo=bad&tfo&simplerules&provider=clash&age-public-key=x&area=hk")

	if params.Level != "" || params.Type != "love" || params.TFO != nil || params.SimpleRules {
		t.Fatalf("invalid reserved values were retained: %+v", params)
	}
	if !reflect.DeepEqual(params.Extras, map[string]string{"area": "hk"}) {
		t.Fatalf("extras = %#v", params.Extras)
	}
	if got, want := params.encode(), "&type=love&area=hk"; got != want {
		t.Fatalf("Encode() = %q, want %q", got, want)
	}
}

func TestParamsTierMigrationPreservesIndependentOptions(t *testing.T) {
	params := parseParams("&lv=1&tfo=false&simplerules=true&area=hk")
	migrated := params.withTierDefaults(queryParams{Type: "love"})

	if migrated.Level != "" || migrated.Type != "love" {
		t.Fatalf("routing defaults were not applied: %+v", migrated)
	}
	if migrated.TFO == nil || *migrated.TFO || !migrated.SimpleRules {
		t.Fatalf("independent switches were not preserved: %+v", migrated)
	}
	if !reflect.DeepEqual(migrated.Extras, map[string]string{"area": "hk"}) {
		t.Fatalf("extras = %#v", migrated.Extras)
	}
}

func TestEffectiveParamsFollowTierDefaults(t *testing.T) {
	t.Setenv("OIX_PARAMS", "")
	homeDir := t.TempDir()

	alu, err := effectiveParamsForPlan(homeDir, planIdentity{Code: "alu", Rank: intPointer(20)})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := alu.encode(), "&lv=2&tfo=true"; got != want {
		t.Fatalf("alu params = %q, want %q", got, want)
	}

	if err := SetParams(homeDir, "&lv=2&tfo=false&simplerules=true&area=hk"); err != nil {
		t.Fatal(err)
	}
	premium, err := effectiveParamsForPlan(homeDir, planIdentity{Code: "platinum", Rank: intPointer(60)})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := premium.encode(), "&type=love&tfo=false&simplerules=true&area=hk"; got != want {
		t.Fatalf("migrated params = %q, want %q", got, want)
	}
}

func TestEffectiveParamsPreserveCustomRouting(t *testing.T) {
	t.Setenv("OIX_PARAMS", "")
	homeDir := t.TempDir()

	if _, err := effectiveParamsForPlan(homeDir, planIdentity{Code: "alu", Rank: intPointer(20)}); err != nil {
		t.Fatal(err)
	}
	if err := SetParams(homeDir, "&lv=1&tfo=false&area=hk"); err != nil {
		t.Fatal(err)
	}
	premium, err := effectiveParamsForPlan(homeDir, planIdentity{Code: "platinum", Rank: intPointer(60)})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := premium.encode(), "&lv=1&tfo=false&area=hk"; got != want {
		t.Fatalf("custom params = %q, want %q", got, want)
	}
}

func TestEnvironmentParamsOverrideStoredOptions(t *testing.T) {
	homeDir := t.TempDir()
	if err := SetParams(homeDir, "&type=love&tfo=true"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OIX_PARAMS", "&lv=1&tfo=false&area=hk")

	params, err := effectiveParamsForPlan(homeDir, planIdentity{Code: "platinum", Rank: intPointer(60)})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := params.encode(), "&lv=1&tfo=false&area=hk"; got != want {
		t.Fatalf("environment params = %q, want %q", got, want)
	}
	state, err := GetParamsState(homeDir)
	if err != nil {
		t.Fatal(err)
	}
	if state.Source != "environment" || state.Params != "&lv=1&tfo=false&area=hk" {
		t.Fatalf("state = %+v", state)
	}
}

func TestEnvironmentParamsRejectOversizedValue(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("OIX_PARAMS", strings.Repeat("x", maxParamsLength+1))

	_, err := effectiveParamsForPlan(homeDir, planIdentity{Code: "platinum", Rank: intPointer(60)})
	if !errors.Is(err, ErrParamsTooLong) {
		t.Fatalf("error = %v, want ErrParamsTooLong", err)
	}
}

func TestSetParamsRejectsOversizedValue(t *testing.T) {
	t.Setenv("OIX_PARAMS", "")
	err := SetParams(t.TempDir(), strings.Repeat("x", maxParamsLength+1))
	if !errors.Is(err, ErrParamsTooLong) {
		t.Fatalf("error = %v, want ErrParamsTooLong", err)
	}
}

func TestParamsFilesUsePrivatePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission bits are not portable on Windows")
	}
	t.Setenv("OIX_PARAMS", "")
	homeDir := t.TempDir()
	if _, err := effectiveParamsForPlan(homeDir, planIdentity{Code: "platinum", Rank: intPointer(60)}); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{paramsFileName, defaultParamsFileName} {
		info, err := os.Stat(filepath.Join(homeDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
			t.Fatalf("%s permissions = %o, want %o", name, got, want)
		}
	}
}

func TestWriteParamsFileTightensExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission bits are not portable on Windows")
	}
	path := filepath.Join(t.TempDir(), paramsFileName)
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeParamsFile(path, "&tfo=true"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("params permissions = %o, want 600", got)
	}
}

func TestEnvironmentParamsRejectMutations(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("OIX_PARAMS", "&type=love")

	if err := SetParams(homeDir, "&lv=1"); !errors.Is(err, ErrParamsEnvironmentOverride) {
		t.Fatalf("SetParams error = %v, want ErrParamsEnvironmentOverride", err)
	}
	if err := ResetParams(homeDir); !errors.Is(err, ErrParamsEnvironmentOverride) {
		t.Fatalf("ResetParams error = %v, want ErrParamsEnvironmentOverride", err)
	}
}

func TestEffectiveParamsStripUnsupportedEmergencyLevel(t *testing.T) {
	t.Setenv("OIX_PARAMS", "")
	homeDir := t.TempDir()
	if _, err := effectiveParamsForPlan(homeDir, planIdentity{Code: "platinum", Rank: intPointer(60)}); err != nil {
		t.Fatal(err)
	}
	if err := SetParams(homeDir, "&lv=2&tfo=false&area=hk"); err != nil {
		t.Fatal(err)
	}

	params, err := effectiveParamsForPlan(homeDir, planIdentity{Code: "iron", Rank: intPointer(10)})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := params.encode(), "&tfo=false&area=hk"; got != want {
		t.Fatalf("downgraded params = %q, want %q", got, want)
	}
}
