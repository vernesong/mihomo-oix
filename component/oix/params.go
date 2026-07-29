package oix

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	modeOverseas          = "overseas"
	modeEmergency         = "emergency"
	modePremium           = "premium"
	maxParamsLength       = 8192
	paramsFileName        = ".oix_params"
	defaultParamsFileName = ".oix_default_params"
)

type subscriptionTier uint8

const (
	tierNone subscriptionTier = iota
	tierAlu
	tierPremium
)

type queryParams struct {
	Mode        string
	TFO         *bool
	SimpleRules bool
	Extras      map[string]string
}

type ParamsState struct {
	Params        string `json:"params"`
	DefaultParams string `json:"default_params"`
	Source        string `json:"source"`
}

var paramsMu sync.Mutex

var (
	ErrParamsTooLong             = errors.New("oix params are too long")
	ErrParamsEnvironmentOverride = errors.New("oix params are controlled by OIX_PARAMS")
	ErrParamsInvalid             = errors.New("oix params contain an invalid routing parameter")
)

func parseParams(raw string) queryParams {
	raw = strings.TrimLeft(strings.TrimSpace(raw), "?&")
	if raw == "" {
		return queryParams{}
	}

	params := queryParams{Extras: map[string]string{}}
	var explicitMode string
	legacyPremium := false
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}

		keyRaw, valueRaw, hasValue := strings.Cut(pair, "=")
		key := decodeQueryComponent(keyRaw)
		keyLower := strings.ToLower(key)
		if !hasValue {
			if !isReservedParamKey(key) && key != "" {
				params.Extras[key] = ""
			}
			continue
		}

		value := decodeQueryComponent(valueRaw)
		switch keyLower {
		case "mode":
			normalized := strings.ToLower(strings.TrimSpace(value))
			if normalized == modeOverseas || normalized == modeEmergency || normalized == modePremium {
				explicitMode = normalized
			}
		case "type":
			legacyPremium = isLegacyPremiumType(value) || legacyPremium
		case "tfo":
			switch value {
			case "true":
				params.TFO = boolPointer(true)
			case "false":
				params.TFO = boolPointer(false)
			default:
				params.TFO = nil
			}
		case "simplerules":
			params.SimpleRules = value == "true"
		default:
			if !isReservedParamKey(key) && key != "" {
				params.Extras[key] = value
			}
		}
	}

	params.Mode = explicitMode
	if params.Mode == "" && legacyPremium {
		params.Mode = modePremium
	}

	if len(params.Extras) == 0 {
		params.Extras = nil
	}
	return params
}

func (p queryParams) encode() string {
	segments := make([]string, 0, 4+len(p.Extras))
	if p.Mode == modeOverseas || p.Mode == modeEmergency || p.Mode == modePremium {
		segments = append(segments, "mode="+p.Mode)
	}
	if p.TFO != nil {
		segments = append(segments, "tfo="+strconv.FormatBool(*p.TFO))
	}
	if p.SimpleRules {
		segments = append(segments, "simplerules=true")
	}

	keys := make([]string, 0, len(p.Extras))
	for key := range p.Extras {
		if key != "" && !isReservedParamKey(key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		encodedKey := encodeQueryComponent(key)
		value := p.Extras[key]
		if value == "" {
			segments = append(segments, encodedKey)
		} else {
			segments = append(segments, encodedKey+"="+encodeQueryComponent(value))
		}
	}

	if len(segments) == 0 {
		return ""
	}
	return "&" + strings.Join(segments, "&")
}

func (p queryParams) query() string {
	encoded := p.encode()
	if encoded == "" {
		return ""
	}
	return "?" + strings.TrimPrefix(encoded, "&")
}

func (p queryParams) withTierDefaults(defaults queryParams) queryParams {
	p.Mode = defaults.Mode
	return p
}

func (p queryParams) withDefaultTFO() queryParams {
	if p.TFO == nil {
		p.TFO = boolPointer(true)
	}
	return p
}

func (p queryParams) adjustedForTier(tier subscriptionTier) queryParams {
	if !tierSupportsMode(tier, p.Mode) {
		p.Mode = defaultParamsForTier(tier).Mode
	}
	return p
}

func tierSupportsMode(tier subscriptionTier, mode string) bool {
	switch mode {
	case "", modeOverseas:
		return true
	case modeEmergency:
		return tier != tierNone
	case modePremium:
		return tier == tierPremium
	default:
		return false
	}
}

func (p queryParams) routeEncoding() string {
	return queryParams{Mode: p.Mode}.encode()
}

func tierForPlan(plan planIdentity) subscriptionTier {
	if len(plan.NodeAccess) > 0 {
		hasDefinedAccess := false
		hasOptimized := false
		for _, rawTag := range plan.NodeAccess {
			tag := strings.ToLower(strings.TrimSpace(rawTag))
			if tag == "" {
				continue
			}
			hasDefinedAccess = true
			switch tag {
			case "fusion", "fusion_advanced", "fusion_premium", "gia":
				return tierPremium
			case "cia", "ixp":
				hasOptimized = true
			}
		}
		if hasDefinedAccess {
			if hasOptimized {
				return tierAlu
			}
			return tierNone
		}
	}

	if plan.Rank != nil {
		switch {
		case *plan.Rank >= 40:
			return tierPremium
		case *plan.Rank >= 20:
			return tierAlu
		default:
			return tierNone
		}
	}

	switch strings.ToLower(strings.TrimSpace(plan.Code)) {
	case "alu", "bronze":
		return tierAlu
	case "silver", "gold", "platinum", "diamond", "developer", "team", "enterprise", "realtime", "titanium":
		return tierPremium
	case "no_plan", "iron":
		return tierNone
	}

	switch strings.ToLower(strings.TrimSpace(plan.Name)) {
	case "", "null", "no plan", "default", "pass iron":
		return tierNone
	case "pass alu", "pass bronze":
		return tierAlu
	default:
		return tierPremium
	}
}

func defaultParamsForTier(tier subscriptionTier) queryParams {
	switch tier {
	case tierAlu:
		return queryParams{Mode: modeEmergency}
	case tierPremium:
		return queryParams{Mode: modePremium}
	default:
		return queryParams{}
	}
}

func defaultParamsForPlan(plan planIdentity) queryParams {
	return defaultParamsForTier(tierForPlan(plan))
}

func effectiveParamsForPlan(homeDir string, plan planIdentity) (queryParams, error) {
	paramsMu.Lock()
	defer paramsMu.Unlock()

	currentRaw, environmentOverride, hasCurrent, err := readCurrentParams(homeDir)
	if err != nil {
		return queryParams{}, err
	}
	oldDefaultRaw, _, err := readParamsFile(defaultParamsFilePath(homeDir))
	if err != nil {
		return queryParams{}, err
	}
	oldDefaultRoute := parseParams(oldDefaultRaw).routeEncoding()

	tier := tierForPlan(plan)
	newDefault := defaultParamsForPlan(plan)
	newDefaultRaw := newDefault.encode()
	current := parseParams(currentRaw)
	if !environmentOverride && (!hasCurrent || (current.routeEncoding() == oldDefaultRoute && oldDefaultRoute != newDefaultRaw)) {
		current = current.withTierDefaults(newDefault)
	}
	current = current.adjustedForTier(tier).withDefaultTFO()

	currentEncoded := current.encode()
	if !environmentOverride && (!hasCurrent || currentRaw != currentEncoded) {
		if err := writeParamsFile(paramsFilePath(homeDir), currentEncoded); err != nil {
			return queryParams{}, err
		}
	}
	if oldDefaultRaw != newDefaultRaw {
		if err := writeParamsFile(defaultParamsFilePath(homeDir), newDefaultRaw); err != nil {
			return queryParams{}, err
		}
	}

	return current, nil
}

func effectiveParamsWithoutPlan(homeDir string) (queryParams, error) {
	paramsMu.Lock()
	defer paramsMu.Unlock()

	raw, _, _, err := readCurrentParams(homeDir)
	if err != nil {
		return queryParams{}, err
	}
	return parseParams(raw).withDefaultTFO(), nil
}

func GetParamsState(homeDir string) (ParamsState, error) {
	paramsMu.Lock()
	defer paramsMu.Unlock()
	params, environmentOverride, exists, err := readCurrentParams(homeDir)
	if err != nil {
		return ParamsState{}, err
	}
	source := "file"
	if environmentOverride {
		params = parseParams(params).withDefaultTFO().encode()
		source = "environment"
	} else if !exists {
		source = "default"
	}
	defaults, _, err := readParamsFile(defaultParamsFilePath(homeDir))
	if err != nil {
		return ParamsState{}, err
	}
	return ParamsState{Params: params, DefaultParams: defaults, Source: source}, nil
}

func readCurrentParams(homeDir string) (params string, environmentOverride, exists bool, err error) {
	params, environmentOverride, err = environmentParams()
	if err != nil {
		return "", false, false, err
	}
	if environmentOverride {
		return params, true, true, nil
	}
	params, exists, err = readParamsFile(paramsFilePath(homeDir))
	return params, false, exists, err
}

func SetParams(homeDir, raw string) error {
	paramsMu.Lock()
	defer paramsMu.Unlock()

	if len(raw) > maxParamsLength {
		return ErrParamsTooLong
	}
	if _, override, err := environmentParams(); err != nil {
		return err
	} else if override {
		return ErrParamsEnvironmentOverride
	}
	if err := validateEditableParams(raw); err != nil {
		return err
	}
	params := parseParams(raw).withDefaultTFO()
	return writeParamsFile(paramsFilePath(homeDir), params.encode())
}

func ResetParams(homeDir string) error {
	paramsMu.Lock()
	defer paramsMu.Unlock()

	if _, override, err := environmentParams(); err != nil {
		return err
	} else if override {
		return ErrParamsEnvironmentOverride
	}

	err := os.Remove(paramsFilePath(homeDir))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func clearParams(homeDir string) {
	paramsMu.Lock()
	defer paramsMu.Unlock()

	_ = os.Remove(paramsFilePath(homeDir))
	_ = os.Remove(defaultParamsFilePath(homeDir))
}

func paramsFilePath(homeDir string) string {
	return filepath.Join(homeDir, paramsFileName)
}

func defaultParamsFilePath(homeDir string) string {
	return filepath.Join(homeDir, defaultParamsFileName)
}

func environmentParams() (string, bool, error) {
	value := strings.TrimSpace(os.Getenv("OIX_PARAMS"))
	if len(value) > maxParamsLength {
		return "", false, ErrParamsTooLong
	}
	return value, value != "", nil
}

func readParamsFile(path string) (string, bool, error) {
	data, err := readPrivateFile(path)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if len(data) > maxParamsLength {
		return "", false, ErrParamsTooLong
	}
	return strings.TrimSpace(string(data)), true, nil
}

func writeParamsFile(path, value string) error {
	if filepath.Dir(path) == "." {
		return errors.New("oix params home directory is not set")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writePrivateFile(path, []byte(value))
}

func isReservedParamKey(key string) bool {
	switch strings.ToLower(key) {
	case "mode", "type", "tfo", "simplerules", "flclash", "age-public-key", "age_public_key", "provider", "anywhere", "debug", "client":
		return true
	default:
		return false
	}
}

func validateEditableParams(raw string) error {
	raw = strings.TrimLeft(strings.TrimSpace(raw), "?&")
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		keyRaw, valueRaw, hasValue := strings.Cut(pair, "=")
		key := strings.ToLower(decodeQueryComponent(keyRaw))
		switch key {
		case "mode", "type":
			if !hasValue {
				return fmt.Errorf("%w: %s", ErrParamsInvalid, key)
			}
			value := strings.ToLower(strings.TrimSpace(decodeQueryComponent(valueRaw)))
			valid := false
			switch key {
			case "mode":
				valid = value == modeOverseas || value == modeEmergency || value == modePremium
			case "type":
				valid = isLegacyPremiumType(value)
			}
			if !valid {
				return fmt.Errorf("%w: %s", ErrParamsInvalid, key)
			}
		}
	}
	return nil
}

func isLegacyPremiumType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "love", "latest", "extreme":
		return true
	default:
		return false
	}
}

func decodeQueryComponent(value string) string {
	decoded, err := url.QueryUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}

func encodeQueryComponent(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func boolPointer(value bool) *bool {
	return &value
}
