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
	params := parseParams("&mode=emergency&type=love&tfo=false&simplerules=true&area=hk&custom=1")

	if params.Mode != modeEmergency {
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
	if got, want := params.encode(), "&mode=emergency&tfo=false&simplerules=true&area=hk&custom=1"; got != want {
		t.Fatalf("Encode() = %q, want %q", got, want)
	}
}

func TestValidModeWinsOverPremiumTypeAndInvalidRepeatedMode(t *testing.T) {
	params := parseParams("&mode=overseas&type=love&mode=bad&area=hk")

	if params.Mode != modeOverseas {
		t.Fatalf("unexpected routing params: %+v", params)
	}
	if got, want := params.encode(), "&mode=overseas&area=hk"; got != want {
		t.Fatalf("encode() = %q, want %q", got, want)
	}
}

func TestParamsRoundTripEncoding(t *testing.T) {
	params := parseParams("&type=relay&space=a%20b&plus=a+b&ampersand=a%26b")
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
	if strings.Contains(encoded, "type=") {
		t.Fatalf("unsupported type was retained: %q", encoded)
	}
}

func TestObsoleteTypeFilterIsAlwaysDropped(t *testing.T) {
	for _, obsolete := range []string{"love", "latest", "extreme", "relay", "cusrelay", "gamer", "back", "all", "default"} {
		if got := parseParams("&type=" + obsolete).encode(); got != "" {
			t.Fatalf("obsolete type %q retained as %q", obsolete, got)
		}
	}
	if got := parseParams("&mode=fusion").encode(); got != "" {
		t.Fatalf("unsupported fusion mode retained as %q", got)
	}
}

func TestParamsRejectInvalidAndInternalKeys(t *testing.T) {
	params := parseParams("&mode=bad&MODE=bad&type=love&type&lv=2&nolv=1&tfo=bad&tfo&simplerules&provider=clash&age-public-key=x&=orphan&area=hk")

	if params.Mode != "" || params.TFO != nil || params.SimpleRules {
		t.Fatalf("invalid reserved values were retained: %+v", params)
	}
	if !reflect.DeepEqual(params.Extras, map[string]string{"area": "hk"}) {
		t.Fatalf("extras = %#v", params.Extras)
	}
	if got, want := params.encode(), "&area=hk"; got != want {
		t.Fatalf("Encode() = %q, want %q", got, want)
	}
}

func TestParamsTierMigrationPreservesIndependentOptions(t *testing.T) {
	params := parseParams("&mode=overseas&tfo=false&simplerules=true&area=hk")
	migrated := params.withTierDefaults(queryParams{Mode: modePremium})

	if migrated.Mode != modePremium {
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
	if got, want := alu.encode(), "&mode=emergency&tfo=true"; got != want {
		t.Fatalf("alu params = %q, want %q", got, want)
	}

	if err := SetParams(homeDir, "&mode=emergency&tfo=false&simplerules=true&area=hk"); err != nil {
		t.Fatal(err)
	}
	premium, err := effectiveParamsForPlan(homeDir, planIdentity{Code: "platinum", Rank: intPointer(60)})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := premium.encode(), "&mode=premium&tfo=false&simplerules=true&area=hk"; got != want {
		t.Fatalf("migrated params = %q, want %q", got, want)
	}
}

func TestEffectiveParamsMigrateLegacyPremiumDefault(t *testing.T) {
	t.Setenv("OIX_PARAMS", "")
	homeDir := t.TempDir()
	if err := writeParamsFile(paramsFilePath(homeDir), "&type=love&tfo=false&area=hk"); err != nil {
		t.Fatal(err)
	}
	if err := writeParamsFile(defaultParamsFilePath(homeDir), "&type=love"); err != nil {
		t.Fatal(err)
	}

	params, err := effectiveParamsForPlan(homeDir, planIdentity{Code: "alu", Rank: intPointer(20)})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := params.encode(), "&mode=emergency&tfo=false&area=hk"; got != want {
		t.Fatalf("migrated params = %q, want %q", got, want)
	}
	if raw, _, err := readParamsFile(paramsFilePath(homeDir)); err != nil || raw != "&mode=emergency&tfo=false&area=hk" {
		t.Fatalf("stored params = %q, err = %v", raw, err)
	}
	if raw, _, err := readParamsFile(defaultParamsFilePath(homeDir)); err != nil || raw != "&mode=emergency" {
		t.Fatalf("stored default = %q, err = %v", raw, err)
	}
}

func TestEffectiveParamsPreserveCustomRouting(t *testing.T) {
	t.Setenv("OIX_PARAMS", "")
	homeDir := t.TempDir()

	if _, err := effectiveParamsForPlan(homeDir, planIdentity{Code: "alu", Rank: intPointer(20)}); err != nil {
		t.Fatal(err)
	}
	if err := SetParams(homeDir, "&mode=overseas&tfo=false&area=hk"); err != nil {
		t.Fatal(err)
	}
	premium, err := effectiveParamsForPlan(homeDir, planIdentity{Code: "platinum", Rank: intPointer(60)})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := premium.encode(), "&mode=overseas&tfo=false&area=hk"; got != want {
		t.Fatalf("custom params = %q, want %q", got, want)
	}
}

func TestEffectiveParamsSurvivePersistenceFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the read-only directory used to force a write failure")
	}
	t.Setenv("OIX_PARAMS", "")
	homeDir := t.TempDir()
	if err := os.Chmod(homeDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(homeDir, 0o755) })

	params, err := effectiveParamsForPlan(homeDir, planIdentity{Code: "alu", Rank: intPointer(20)})
	if err != nil {
		t.Fatalf("unpersisted options must still resolve: %v", err)
	}
	if got, want := params.encode(), "&mode=emergency&tfo=true"; got != want {
		t.Fatalf("params = %q, want %q", got, want)
	}
}

func TestEnvironmentParamsOverrideStoredOptions(t *testing.T) {
	homeDir := t.TempDir()
	if err := SetParams(homeDir, "&mode=premium&tfo=true"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OIX_PARAMS", "&mode=overseas&tfo=false&area=hk")

	params, err := effectiveParamsForPlan(homeDir, planIdentity{Code: "platinum", Rank: intPointer(60)})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := params.encode(), "&mode=overseas&tfo=false&area=hk"; got != want {
		t.Fatalf("environment params = %q, want %q", got, want)
	}
	state, err := GetParamsState(homeDir)
	if err != nil {
		t.Fatal(err)
	}
	if state.Source != "environment" || state.Params != "&mode=overseas&tfo=false&area=hk" {
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

func TestSetParamsRejectsLossyRoutingValues(t *testing.T) {
	t.Setenv("OIX_PARAMS", "")
	for _, raw := range []string{"&mode=fusion", "&mode"} {
		if err := SetParams(t.TempDir(), raw); !errors.Is(err, ErrParamsInvalid) {
			t.Fatalf("SetParams(%q) error = %v, want ErrParamsInvalid", raw, err)
		}
	}
	obsolete := t.TempDir()
	if err := SetParams(obsolete, "&type=relay&lv=2"); err != nil {
		t.Fatalf("obsolete keys rejected: %v", err)
	}
	if raw, _, err := readParamsFile(paramsFilePath(obsolete)); err != nil || raw != "&tfo=true" {
		t.Fatalf("stored obsolete params = %q, err = %v", raw, err)
	}
	homeDir := t.TempDir()
	if err := SetParams(homeDir, "??&MODE=Premium"); err != nil {
		t.Fatalf("case-insensitive valid mode rejected: %v", err)
	}
	if raw, _, err := readParamsFile(paramsFilePath(homeDir)); err != nil || raw != "&mode=premium&tfo=true" {
		t.Fatalf("stored normalized params = %q, err = %v", raw, err)
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

func TestWriteParamsFileDoesNotFollowSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges on Windows")
	}
	homeDir := t.TempDir()
	victimPath := filepath.Join(homeDir, "victim")
	if err := os.WriteFile(victimPath, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	paramsPath := filepath.Join(homeDir, paramsFileName)
	if err := os.Symlink(victimPath, paramsPath); err != nil {
		t.Fatal(err)
	}

	if err := writeParamsFile(paramsPath, "&tfo=true"); err != nil {
		t.Fatal(err)
	}
	victim, err := os.ReadFile(victimPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(victim) != "keep" {
		t.Fatalf("symlink target was overwritten: %q", victim)
	}
	info, err := os.Lstat(paramsPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("params path remained a symlink")
	}
}

func TestReadParamsFileRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges on Windows")
	}
	homeDir := t.TempDir()
	victimPath := filepath.Join(homeDir, "victim")
	if err := os.WriteFile(victimPath, []byte("&secret=linked"), 0o644); err != nil {
		t.Fatal(err)
	}
	paramsPath := filepath.Join(homeDir, paramsFileName)
	if err := os.Symlink(victimPath, paramsPath); err != nil {
		t.Fatal(err)
	}

	if _, _, err := readParamsFile(paramsPath); err == nil {
		t.Fatal("readParamsFile accepted a symlink")
	}
	info, err := os.Stat(victimPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("symlink target permissions = %o, want 644", got)
	}
}

func TestReadParamsFileRejectsOversizedValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), paramsFileName)
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxParamsLength+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readParamsFile(path); !errors.Is(err, ErrParamsTooLong) {
		t.Fatalf("readParamsFile error = %v, want ErrParamsTooLong", err)
	}
}

func TestEnvironmentParamsRejectMutations(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("OIX_PARAMS", "&mode=premium")

	if err := SetParams(homeDir, "&mode=overseas"); !errors.Is(err, ErrParamsEnvironmentOverride) {
		t.Fatalf("SetParams error = %v, want ErrParamsEnvironmentOverride", err)
	}
	if err := ResetParams(homeDir); !errors.Is(err, ErrParamsEnvironmentOverride) {
		t.Fatalf("ResetParams error = %v, want ErrParamsEnvironmentOverride", err)
	}
}

func TestEffectiveParamsAdjustUnsupportedRoutingMode(t *testing.T) {
	t.Setenv("OIX_PARAMS", "")
	homeDir := t.TempDir()
	if _, err := effectiveParamsForPlan(homeDir, planIdentity{Code: "platinum", Rank: intPointer(60)}); err != nil {
		t.Fatal(err)
	}
	if err := SetParams(homeDir, "&mode=emergency&tfo=false&area=hk"); err != nil {
		t.Fatal(err)
	}

	params, err := effectiveParamsForPlan(homeDir, planIdentity{Code: "iron", Rank: intPointer(10)})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := params.encode(), "&tfo=false&area=hk"; got != want {
		t.Fatalf("downgraded params = %q, want %q", got, want)
	}

	if err := SetParams(homeDir, "&mode=premium&tfo=false&area=hk"); err != nil {
		t.Fatal(err)
	}
	params, err = effectiveParamsForPlan(homeDir, planIdentity{Code: "alu", Rank: intPointer(20)})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := params.encode(), "&mode=emergency&tfo=false&area=hk"; got != want {
		t.Fatalf("alu-adjusted params = %q, want %q", got, want)
	}
}
