package oix

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/age"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/oix/oixdns"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"gopkg.in/yaml.v3"
)

var (
	AppSecret      string
	ApiDomains     string
	SpareApiDomain string

	ageSecretKey   string
	agePublicKey   string
	ageKeyInitOnce sync.Once

	oixProviderName string
	providerNameMu  sync.RWMutex

	periodicCancel   context.CancelFunc
	periodicDone     chan struct{}
	periodicDir      string
	periodicHome     string
	periodicMu       sync.RWMutex
	providerUpdateMu sync.Mutex

	oixHTTPClient = newOixHTTPClient()
)

var (
	ErrAuthFailed = errors.New("authentication failed")
	ErrNoToken    = errors.New("OIX_TOKEN not set")
	ErrNoDomains  = errors.New("no API domains configured")
)

var (
	tokenMu    sync.RWMutex
	loginToken string
)

func SetToken(token string) {
	tokenMu.Lock()
	loginToken = normalizeToken(token)
	tokenMu.Unlock()
}

func normalizeToken(token string) string {
	token = strings.TrimSpace(token)
	if len(token) >= 7 && strings.EqualFold(token[:7], "bearer ") {
		token = strings.TrimSpace(token[7:])
	}
	return token
}

func CurrentToken() string {
	tokenMu.RLock()
	defer tokenMu.RUnlock()
	return loginToken
}

func getToken() string {
	if t := CurrentToken(); t != "" {
		return t
	}
	return normalizeToken(os.Getenv("OIX_TOKEN"))
}

func HasToken() bool {
	return getToken() != ""
}

const (
	defaultProviderFile = "oixCloud"
	defaultProviderDir  = "proxy_providers"
)

const (
	maxRetries              = 2
	totalTimeout            = 30 * time.Second
	planTimeout             = 5 * time.Second
	hedgeDelay              = 250 * time.Millisecond
	maxManagedResponseBytes = 16 << 20
	maxAccountResponseBytes = 1 << 20
	maxErrorResponseBytes   = 1024
)

const oixUserAgent = "OpenClash for oixCloud"

type apiResponse struct {
	Ret    int    `json:"ret"`
	Msg    string `json:"msg"`
	Config string `json:"config"`
}

type planIdentity struct {
	Code string
	Rank *int
	Name string
}

type informationData struct {
	Plan     string `json:"plan"`
	PlanCode string `json:"plan_code"`
	PlanRank *int   `json:"plan_rank"`
}

type informationResponse struct {
	Ret  int              `json:"ret"`
	Msg  string           `json:"msg"`
	Data *informationData `json:"data"`
}

func IsAuthError(err error) bool {
	return errors.Is(err, ErrAuthFailed)
}

func IsConfigError(err error) bool {
	return errors.Is(err, ErrNoToken) || errors.Is(err, ErrNoDomains)
}

func ageKeyFilePath(homeDir string) string {
	return filepath.Join(homeDir, ".oix_age_key")
}

func ageKeyPair() (secretKey, publicKey string) {
	ageKeyInitOnce.Do(func() {
		homeDir := C.Path.HomeDir()
		if homeDir != "" {
			keyPath := ageKeyFilePath(homeDir)
			if data, err := readPrivateFile(keyPath); err == nil {
				sk := strings.TrimSpace(string(data))
				if pks, err := age.ToPublicKeys(sk); err == nil && len(pks) > 0 {
					ageSecretKey = sk
					agePublicKey = pks[0]
					return
				}
			}
		}
		sk, pk, err := age.GenX25519KeyPair()
		if err != nil {
			log.Warnln("[oixCloud] failed to generate age key pair: %s", err)
			return
		}
		ageSecretKey = sk
		agePublicKey = pk
		if homeDir != "" {
			if err := writePrivateFile(ageKeyFilePath(homeDir), []byte(sk)); err != nil {
				log.Warnln("[oixCloud] persist age key failed: %s", err)
			}
		}
	})
	return ageSecretKey, agePublicKey
}

func ProviderConfig(relPath string, base map[string]any) map[string]any {
	ageKeyPair()

	oixCfg := map[string]any{
		"type":           "file",
		"path":           "./" + relPath,
		"age-secret-key": ageSecretKey,
		"health-check": map[string]any{
			"enable":   true,
			"url":      "http://cp.cloudflare.com/generate_204",
			"interval": 300,
		},
	}

	if base != nil {
		if userHC, ok := base["health-check"]; ok {
			if userHCMap, ok := userHC.(map[string]any); ok {
				if oixHC, ok := oixCfg["health-check"].(map[string]any); ok {
					hcMerged := make(map[string]any, len(oixHC)+len(userHCMap))
					for hk, hv := range oixHC {
						hcMerged[hk] = hv
					}
					for hk, hv := range userHCMap {
						hcMerged[hk] = hv
					}
					oixCfg["health-check"] = hcMerged
				}
			}
		}
		for k, v := range base {
			if _, exists := oixCfg[k]; exists {
				continue
			}
			oixCfg[k] = v
		}
	}

	return oixCfg
}

func ProviderDirectory(homeDir, preferredPath string, providerPaths []string) string {
	if dir, ok := relativeProviderDirectory(homeDir, preferredPath); ok {
		return dir
	}
	directories := make(map[string]struct{})
	for _, providerPath := range providerPaths {
		if dir, ok := relativeProviderDirectory(homeDir, providerPath); ok {
			directories[dir] = struct{}{}
		}
	}
	if len(directories) == 1 {
		for dir := range directories {
			return dir
		}
	}
	return defaultProviderDir
}

func relativeProviderDirectory(homeDir, providerPath string) (string, bool) {
	if providerPath == "" {
		return "", false
	}
	dir, err := filepath.Rel(homeDir, filepath.Dir(providerPath))
	return dir, err == nil
}

func Ensure(dir, homeDir string, providerExists bool) (bool, error) {
	providerUpdateMu.Lock()
	defer providerUpdateMu.Unlock()

	token := getToken()
	if token == "" {
		oixdns.ClearEnsured()
		return false, ErrNoToken
	}
	urls := apiBaseURLs()
	if len(urls) == 0 {
		oixdns.ClearEnsured()
		return false, ErrNoDomains
	}

	log.Infoln("[oixCloud] fetching provider...")

	config, err := fetchBest(context.Background(), token, urls, homeDir)
	if err != nil {
		if IsAuthError(err) {
			oixdns.ClearEnsured()
			log.Warnln("[oixCloud] auth failed for provider [%s]", ProviderFile())
		} else {
			log.Warnln("[oixCloud] config fetch failed: %s", err)
			ensureFromDisk(dir, homeDir)
		}
		return false, err
	}
	if len(config) == 0 {
		log.Warnln("[oixCloud] ensure failed, no provider found for [%s]", ProviderFile())
		ensureFromDisk(dir, homeDir)
		return false, nil
	}
	ok := saveResult(dir, homeDir, config)
	if !ok {
		return false, errors.New("save failed")
	}
	oixdns.SetEnsured()
	if providerExists {
		log.Infoln("[oixCloud] provider [%s] already exists, file updated", ProviderFile())
	} else {
		log.Infoln("[oixCloud] provider fetched successfully: [%s]", ProviderFile())
	}
	return true, nil
}

func SetProviderName(name string) {
	providerNameMu.Lock()
	defer providerNameMu.Unlock()
	oixProviderName = validProviderName(name)
}

func ensureFromDisk(dir, homeDir string) {
	raw, err := os.ReadFile(filepath.Join(homeDir, dir, ProviderFile()))
	if err != nil || !isAgeArmored(raw) || ageSecretKey == "" {
		return
	}
	plain, err := age.DecryptBytes(raw, ageSecretKey)
	if err != nil {
		return
	}
	applyManagedDNSConfig(plain)
	oixdns.SetEnsured()
}

const defaultUpdateInterval = 24 * time.Hour

func StartPeriodicUpdate(dir, homeDir string) {
	interval := defaultUpdateInterval
	if s := os.Getenv("OIX_UPDATE_INTERVAL"); s != "" {
		const maxIntervalSeconds = int64(^uint64(0)>>1) / int64(time.Second)
		if seconds, err := strconv.ParseInt(s, 10, 64); err == nil && seconds > 0 && seconds <= maxIntervalSeconds {
			interval = time.Duration(seconds) * time.Second
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	periodicMu.Lock()
	stopPeriodicLocked()
	periodicCancel = cancel
	periodicDone = done
	periodicDir = dir
	periodicHome = homeDir

	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := runPeriodicUpdate(ctx, dir, homeDir); err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Warnln("[oixCloud] periodic update failed: %s", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	periodicMu.Unlock()
}

func runPeriodicUpdate(ctx context.Context, dir, homeDir string) error {
	providerUpdateMu.Lock()
	defer providerUpdateMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	token := getToken()
	if token == "" {
		return nil
	}
	urls := apiBaseURLs()
	if len(urls) == 0 {
		return nil
	}
	config, err := fetchBest(ctx, token, urls, homeDir)
	if err != nil {
		return err
	}
	if len(config) == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if saveResult(dir, homeDir, config) {
		log.Infoln("[oixCloud] periodic update saved to %s", filepath.Join(homeDir, dir, ProviderFile()))
	}
	return nil
}

func StopPeriodicUpdate() {
	periodicMu.Lock()
	stopPeriodicLocked()
	periodicMu.Unlock()
}

func stopPeriodicLocked() {
	if periodicCancel != nil {
		periodicCancel()
	}
	if periodicDone != nil {
		<-periodicDone
	}
	periodicCancel = nil
	periodicDone = nil
}

func ForceUpdate() error {
	dir, homeDir := providerPaths()
	if dir == "" {
		return errors.New("periodic update not started")
	}
	_, err := Ensure(dir, homeDir, true)
	return err
}

func SetProviderPaths(dir, homeDir string) {
	periodicMu.Lock()
	defer periodicMu.Unlock()
	periodicDir = dir
	periodicHome = homeDir
}

func providerPaths() (dir, homeDir string) {
	periodicMu.RLock()
	defer periodicMu.RUnlock()
	return periodicDir, periodicHome
}

func tokenFilePath(homeDir string) string {
	return filepath.Join(homeDir, ".oix_token")
}

func LoadPersistedToken(homeDir string) {
	if homeDir == "" || getToken() != "" {
		return
	}
	path := tokenFilePath(homeDir)
	data, err := readPrivateFile(path)
	if err != nil {
		return
	}
	if t := strings.TrimSpace(string(data)); t != "" {
		SetToken(t)
	}
}

func persistToken(homeDir, token string) error {
	if homeDir == "" {
		return errors.New("home dir not set")
	}
	return writePrivateFile(tokenFilePath(homeDir), []byte(token))
}

func Login(token string) (bool, error) {
	token = normalizeToken(token)
	if token == "" {
		return false, ErrNoToken
	}
	dir, homeDir := providerPaths()
	if dir == "" {
		return false, errors.New("oix provider not initialized")
	}
	prev := CurrentToken()
	SetToken(token)
	ok, err := Ensure(dir, homeDir, true)
	if err != nil || !ok {
		SetToken(prev)
		return ok, err
	}
	if err := persistToken(homeDir, token); err != nil {
		log.Warnln("[oixCloud] persist token failed: %s", err)
	}
	StartPeriodicUpdate(dir, homeDir)
	return true, nil
}

func Logout() {
	SetToken("")
	StopPeriodicUpdate()
	providerUpdateMu.Lock()
	defer providerUpdateMu.Unlock()
	oixdns.ClearEnsured()
	oixdns.ResetManagedDNS()
	dir, homeDir := providerPaths()
	if homeDir != "" {
		_ = os.Remove(tokenFilePath(homeDir))
		clearParams(homeDir)
		if dir != "" {
			_ = os.Remove(filepath.Join(homeDir, dir, ProviderFile()))
		}
	}
}

func IsOixProvider(name string) bool {
	return name == ProviderFile()
}

func fetchBest(parent context.Context, token string, urls []string, homeDir string) ([]byte, error) {
	if len(urls) == 0 {
		return nil, ErrNoDomains
	}
	if ageSecretKey == "" || agePublicKey == "" {
		ageKeyPair()
	}
	if len(urls) == 1 {
		return fetchFrom(parent, token, urls[0], homeDir)
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	type outcome struct {
		config []byte
		err    error
	}
	results := make(chan outcome, len(urls))

	for i, baseURL := range urls {
		go func(index int, baseURL string) {
			if index > 0 {
				timer := time.NewTimer(hedgeDelay)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					results <- outcome{nil, ctx.Err()}
					return
				}
			}
			config, err := fetchFrom(ctx, token, baseURL, homeDir)
			results <- outcome{config, err}
		}(i, baseURL)
	}

	var authErrs []error
	var nonAuthErrs []error
	hadEmpty := false
	for range urls {
		o := <-results
		if o.err == nil {
			if len(o.config) > 0 {
				cancel()
				return o.config, nil
			}
			hadEmpty = true
			continue
		}
		if errors.Is(o.err, ErrAuthFailed) {
			authErrs = append(authErrs, o.err)
		} else {
			nonAuthErrs = append(nonAuthErrs, o.err)
		}
	}
	if hadEmpty {
		return nil, nil
	}
	if len(nonAuthErrs) > 0 {
		return nil, errors.Join(nonAuthErrs...)
	}
	if len(authErrs) > 0 {
		return nil, errors.Join(authErrs...)
	}
	return nil, ErrNoDomains
}

func fetchFrom(ctx context.Context, token, baseURL, homeDir string) ([]byte, error) {
	if agePublicKey == "" {
		return nil, errors.New("age key unavailable")
	}
	if AppSecret == "" {
		return nil, errors.New("app secret unavailable")
	}

	ctx, cancel := context.WithTimeout(ctx, totalTimeout)
	defer cancel()

	planCtx, planCancel := context.WithTimeout(ctx, planTimeout)
	plan, planErr := fetchPlanIdentity(planCtx, token, baseURL)
	planCancel()

	var params queryParams
	var err error
	if planErr == nil {
		params, err = effectiveParamsForPlan(homeDir, plan)
	} else {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		log.Warnln("[oixCloud] account information unavailable, using current options: %s", planErr)
		params, err = effectiveParamsWithoutPlan(homeDir)
	}
	if err != nil {
		return nil, fmt.Errorf("resolve account options: %w", err)
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)

	sig := sign(ts + "." + agePublicKey)

	url := baseURL + "/api/v1/managed/flclash/direct" + params.query()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", oixUserAgent)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Flclash-Timestamp", ts)
	req.Header.Set("X-Flclash-Signature", sig)
	req.Header.Set("X-Flclash-Age-Pubkey", agePublicKey)

	resp, err := oixHTTPDo(req)
	if err != nil {
		return nil, fmt.Errorf("server request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorResponseBytes))
		err := fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
		if resp.StatusCode == http.StatusUnauthorized {
			err = fmt.Errorf("%w: %w", ErrAuthFailed, err)
		}
		return nil, err
	}

	var apiResp apiResponse
	if err := decodeJSONResponse(resp.Body, maxManagedResponseBytes, &apiResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if apiResp.Ret != http.StatusOK {
		return nil, apiResponseError("managed config", apiResp.Ret, apiResp.Msg)
	}

	if err := verifyResponseSignature(ts, apiResp.Config, resp.Header.Get("X-Flclash-Response-Signature")); err != nil {
		return nil, err
	}

	if apiResp.Config == "" {
		return nil, nil
	}
	return decodeArmoredConfig(apiResp.Config)
}

func fetchPlanIdentity(ctx context.Context, token, baseURL string) (planIdentity, error) {
	url := baseURL + "/api/v1/information"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return planIdentity{}, fmt.Errorf("create account request: %w", err)
	}
	req.Header.Set("User-Agent", oixUserAgent)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := oixHTTPDo(req)
	if err != nil {
		return planIdentity{}, fmt.Errorf("account request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorResponseBytes))
		err := fmt.Errorf("account HTTP %d: %s", resp.StatusCode, string(body))
		if resp.StatusCode == http.StatusUnauthorized {
			err = fmt.Errorf("%w: %w", ErrAuthFailed, err)
		}
		return planIdentity{}, err
	}

	var apiResp informationResponse
	if err := decodeJSONResponse(resp.Body, maxAccountResponseBytes, &apiResp); err != nil {
		return planIdentity{}, fmt.Errorf("decode account response: %w", err)
	}
	return planIdentityFromResponse(apiResp)
}

func decodeJSONResponse(reader io.Reader, maxBytes int64, target any) error {
	limited := &io.LimitedReader{R: reader, N: maxBytes + 1}
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(target); err != nil {
		if limited.N == 0 {
			return fmt.Errorf("response exceeds %d bytes", maxBytes)
		}
		return err
	}
	var extra struct{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if limited.N == 0 {
			return fmt.Errorf("response exceeds %d bytes", maxBytes)
		}
		if err == nil {
			return errors.New("response contains multiple JSON values")
		}
		return fmt.Errorf("invalid trailing response data: %w", err)
	}
	if limited.N == 0 {
		return fmt.Errorf("response exceeds %d bytes", maxBytes)
	}
	return nil
}

func planIdentityFromResponse(apiResp informationResponse) (planIdentity, error) {
	if apiResp.Ret != http.StatusOK {
		return planIdentity{}, apiResponseError("account", apiResp.Ret, apiResp.Msg)
	}
	if apiResp.Data == nil {
		return planIdentity{}, errors.New("account response has no data")
	}

	return planIdentity{
		Code: strings.ToLower(strings.TrimSpace(apiResp.Data.PlanCode)),
		Rank: apiResp.Data.PlanRank,
		Name: strings.TrimSpace(apiResp.Data.Plan),
	}, nil
}

func apiResponseError(scope string, ret int, msg string) error {
	err := fmt.Errorf("%s rejected (ret=%d): %s", scope, ret, msg)
	if ret == http.StatusUnauthorized {
		return fmt.Errorf("%w: %w", ErrAuthFailed, err)
	}
	return err
}

func decodeArmoredConfig(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if !isAgeArmored(raw) {
		return nil, errors.New("config not encrypted")
	}
	return raw, nil
}

func sign(message string) string {
	if AppSecret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(AppSecret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyResponseSignature(timestamp, configB64, headerSig string) error {
	if headerSig == "" {
		return errors.New("missing response signature")
	}
	expected := sign(timestamp + "." + configB64)
	if !hmac.Equal([]byte(expected), []byte(headerSig)) {
		return errors.New("response signature mismatch")
	}
	return nil
}

func isAgeArmored(data []byte) bool {
	return bytes.HasPrefix(data, []byte(age.FileHeader))
}

type oixFallbackResolver struct {
	resolver.Resolver
	fallback oixHostResolver
}

func (r oixFallbackResolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return lookupOixHost(ctx, r.Resolver, r.fallbackForHost(host), func(lookupCtx context.Context, current oixHostResolver) ([]netip.Addr, error) {
		return current.LookupIP(lookupCtx, host)
	})
}

func (r oixFallbackResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return lookupOixHost(ctx, r.Resolver, r.fallbackForHost(host), func(lookupCtx context.Context, current oixHostResolver) ([]netip.Addr, error) {
		return current.LookupIPv4(lookupCtx, host)
	})
}

func (r oixFallbackResolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return lookupOixHost(ctx, r.Resolver, r.fallbackForHost(host), func(lookupCtx context.Context, current oixHostResolver) ([]netip.Addr, error) {
		return current.LookupIPv6(lookupCtx, host)
	})
}

func (r oixFallbackResolver) fallbackForHost(host string) oixHostResolver {
	if oixdns.ShouldObfuscate(host) {
		return nil
	}
	return r.fallback
}

func (r oixFallbackResolver) Invalid() bool {
	return true
}

type oixHostResolver interface {
	LookupIP(context.Context, string) ([]netip.Addr, error)
	LookupIPv4(context.Context, string) ([]netip.Addr, error)
	LookupIPv6(context.Context, string) ([]netip.Addr, error)
}

type oixBootstrapResolver struct {
	servers []string
}

var oixBootstrapHostResolver oixHostResolver = &oixBootstrapResolver{
	servers: []string{"223.5.5.5:53", "119.29.29.29:53"},
}

func (r *oixBootstrapResolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookup(ctx, "ip", host)
}

func (r *oixBootstrapResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookup(ctx, "ip4", host)
}

func (r *oixBootstrapResolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookup(ctx, "ip6", host)
}

func (r *oixBootstrapResolver) lookup(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if len(r.servers) == 0 {
		return nil, resolver.ErrIPNotFound
	}
	lookupCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		addresses []netip.Addr
		err       error
	}
	results := make(chan result, len(r.servers))
	for _, server := range r.servers {
		go func() {
			netResolver := &net.Resolver{
				PreferGo: true,
				Dial: func(dialCtx context.Context, dnsNetwork, _ string) (net.Conn, error) {
					return dialer.DialContext(dialCtx, dnsNetwork, server)
				},
			}
			addresses, err := netResolver.LookupNetIP(lookupCtx, network, host)
			results <- result{addresses: addresses, err: err}
		}()
	}

	var errs []error
	for range r.servers {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-results:
			if result.err == nil && len(result.addresses) > 0 {
				return result.addresses, nil
			}
			if result.err == nil {
				result.err = resolver.ErrIPNotFound
			}
			errs = append(errs, result.err)
		}
	}
	return nil, errors.Join(errs...)
}

func lookupOixHost(ctx context.Context, primary, fallback oixHostResolver, lookup func(context.Context, oixHostResolver) ([]netip.Addr, error)) ([]netip.Addr, error) {
	lookupCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		addresses []netip.Addr
		err       error
	}
	results := make(chan result, 2)
	pending := 0
	start := func(current oixHostResolver) {
		if current == nil {
			return
		}
		pending++
		go func() {
			addresses, err := lookup(lookupCtx, current)
			results <- result{addresses: addresses, err: err}
		}()
	}

	start(primary)
	fallbackStarted := primary == nil
	if fallbackStarted {
		start(fallback)
	}
	var hedgeTimer *time.Timer
	var hedge <-chan time.Time
	if primary != nil && fallback != nil {
		hedgeTimer = time.NewTimer(hedgeDelay)
		hedge = hedgeTimer.C
		defer hedgeTimer.Stop()
	}

	var errs []error
	for pending > 0 || !fallbackStarted {
		select {
		case <-ctx.Done():
			return nil, errors.Join(append(errs, ctx.Err())...)
		case <-hedge:
			fallbackStarted = true
			hedge = nil
			start(fallback)
		case result := <-results:
			pending--
			if result.err == nil && len(result.addresses) > 0 {
				return result.addresses, nil
			}
			if result.err == nil {
				result.err = resolver.ErrIPNotFound
			}
			errs = append(errs, result.err)
			if !fallbackStarted {
				fallbackStarted = true
				hedge = nil
				start(fallback)
			}
		}
	}
	if len(errs) == 0 {
		return nil, resolver.ErrIPNotFound
	}
	return nil, errors.Join(errs...)
}

func newOixHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				hostResolver := oixFallbackResolver{Resolver: resolver.DirectHostResolver, fallback: oixBootstrapHostResolver}
				return dialer.DialContext(ctx, network, addr, dialer.WithResolver(hostResolver))
			},
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

func oixHTTPDo(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	deadline := time.Now().Add(totalTimeout)
	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return nil, fmt.Errorf("retry timeout: %w", lastErr)
			}
			return nil, errors.New("retry timeout")
		}
		if i > 0 && req.Body != nil && req.GetBody == nil {
			return nil, errors.New("request body is not replayable")
		}
		if i > 0 {
			timer := time.NewTimer(time.Duration(i) * time.Second)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			}
		}
		attempt := req.Clone(ctx)
		if i > 0 && req.Body != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("replay request body: %w", err)
			}
			attempt.Body = body
		}
		resp, err := oixHTTPClient.Do(attempt)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			resp.Body.Close()
			continue
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("request failed")
	}
	return nil, fmt.Errorf("request failed after %d attempts: %w", maxRetries+1, lastErr)
}

func saveResult(dir, homeDir string, raw []byte) bool {
	p := filepath.Join(homeDir, dir, ProviderFile())

	if !isAgeArmored(raw) || ageSecretKey == "" {
		log.Warnln("[oixCloud] refuse to write unencrypted provider")
		return false
	}
	plain, err := age.DecryptBytes(raw, ageSecretKey)
	if err != nil {
		log.Warnln("[oixCloud] refuse to write invalid encrypted provider")
		return false
	}

	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		log.Warnln("[oixCloud] create provider directory %s: %s", filepath.Dir(p), err)
		return false
	}
	if err := writePrivateFile(p, raw); err != nil {
		log.Warnln("[oixCloud] write file %s: %s", p, err)
		return false
	}
	applyManagedDNSConfig(plain)

	return true
}

func writePrivateFile(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	closed := false
	defer func() {
		if !closed {
			_ = temp.Close()
		}
		_ = os.Remove(tempPath)
	}()

	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	err = temp.Close()
	closed = true
	if err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func readPrivateFile(path string) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.New("private file is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(pathInfo, fileInfo) {
		return nil, errors.New("private file changed while opening")
	}
	if err := file.Chmod(0o600); err != nil {
		log.Warnln("[oixCloud] secure private file failed: %s", err)
	}
	return io.ReadAll(file)
}

type managedConfig struct {
	DNS struct {
		NameServerPolicy map[string]any `yaml:"nameserver-policy"`
	} `yaml:"dns"`
}

func applyManagedDNSConfig(raw []byte) {
	var config managedConfig
	if err := yaml.Unmarshal(raw, &config); err != nil {
		return
	}
	target := oixdns.ManagedNodesDomain()
	patterns := make([]string, 0, len(config.DNS.NameServerPolicy))
	for pattern := range config.DNS.NameServerPolicy {
		patterns = append(patterns, pattern)
	}
	sort.Slice(patterns, func(i, j int) bool {
		domainI, exactI := normalizeManagedDNSPattern(patterns[i])
		domainJ, exactJ := normalizeManagedDNSPattern(patterns[j])
		if exactI != exactJ {
			return exactI
		}
		if domainI != domainJ {
			return domainI < domainJ
		}
		return strings.ToLower(strings.TrimSpace(patterns[i])) < strings.ToLower(strings.TrimSpace(patterns[j]))
	})
	matched := false
	for _, pattern := range patterns {
		domain, _ := normalizeManagedDNSPattern(pattern)
		if domain != target {
			continue
		}
		matched = true
		for _, nameserver := range managedNameServers(config.DNS.NameServerPolicy[pattern]) {
			if addr, ok := managedDNSAddress(nameserver); ok {
				oixdns.ConfigureManagedDNS(domain, addr)
				return
			}
		}
	}
	if !matched {
		oixdns.ResetManagedDNS()
	}
}

func normalizeManagedDNSPattern(pattern string) (domain string, exact bool) {
	pattern = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
	exact = !strings.HasPrefix(pattern, "+.") && !strings.HasPrefix(pattern, ".")
	domain = strings.TrimPrefix(strings.TrimPrefix(pattern, "+."), ".")
	return domain, exact
}

func managedNameServers(value any) []string {
	switch value := value.(type) {
	case string:
		return []string{value}
	case []string:
		return value
	case []any:
		servers := make([]string, 0, len(value))
		for _, item := range value {
			if server, ok := item.(string); ok {
				servers = append(servers, server)
			}
		}
		return servers
	default:
		return nil
	}
}

func managedDNSAddress(nameserver string) (string, bool) {
	nameserver = strings.TrimSpace(nameserver)
	if parsed, err := url.Parse(nameserver); err == nil && parsed.Host != "" {
		if parsed.Scheme != "udp" && parsed.Scheme != "tcp" {
			return "", false
		}
		nameserver = parsed.Host
	}
	host, port, err := net.SplitHostPort(nameserver)
	if err != nil || net.ParseIP(host) == nil {
		return "", false
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", false
	}
	return net.JoinHostPort(host, port), true
}

func ProviderFile() string {
	providerNameMu.RLock()
	name := oixProviderName
	providerNameMu.RUnlock()
	if name = validProviderName(name); name != "" {
		return name
	}
	if name := validProviderName(os.Getenv("OIX_PROVIDER_NAME")); name != "" {
		return name
	}
	return defaultProviderFile
}

func validProviderName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) || !filepath.IsLocal(name) || filepath.Base(name) != name {
		return ""
	}
	return name
}

func apiBaseURLs() []string {
	domains := strings.Split(ApiDomains, ",")
	domains = append(domains, strings.Split(SpareApiDomain, ",")...)
	urls := make([]string, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		baseURL, ok := normalizeAPIBaseURL(domain)
		if !ok {
			continue
		}
		if _, ok := seen[baseURL]; ok {
			continue
		}
		seen[baseURL] = struct{}{}
		urls = append(urls, baseURL)
	}
	return urls
}

func normalizeAPIBaseURL(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return "", false
	}
	parsed.Scheme = "https"
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = strings.TrimRight(parsed.RawPath, "/")
	return parsed.String(), true
}
