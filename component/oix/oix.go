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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/age"
	"github.com/metacubex/mihomo/component/dialer"
	mihomoHttp "github.com/metacubex/mihomo/component/http"
	"github.com/metacubex/mihomo/component/oix/oixdns"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"
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

	oixHTTPClient       = newoixHTTPClient()
	oixRoutedHTTPClient = newoixRoutedHTTPClient()
)

var (
	ErrAuthFailed     = errors.New("authentication failed")
	ErrNoToken        = errors.New("OIX_TOKEN not set")
	ErrNoDomains      = errors.New("no API domains configured")
	ErrNoSubscription = errors.New("no subscription found for this token")
)

var (
	accountMu  sync.Mutex
	tokenMu    sync.RWMutex
	loginToken string
	loggedOut  bool
)

func SetToken(token string) {
	tokenMu.Lock()
	loginToken = normalizeToken(token)
	loggedOut = false
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
	tokenMu.RLock()
	defer tokenMu.RUnlock()
	if loggedOut {
		return ""
	}
	if loginToken != "" {
		return loginToken
	}
	return normalizeToken(os.Getenv("OIX_TOKEN"))
}

func HasToken() bool {
	return getToken() != ""
}

// signedOut reports an explicit logout, as opposed to never having had a token.
func signedOut() bool {
	tokenMu.RLock()
	defer tokenMu.RUnlock()
	return loggedOut
}

const (
	defaultProviderFile = "oixCloud"
	defaultProviderDir  = "proxy_providers"
)

const (
	maxRetries              = 2
	totalTimeout            = 30 * time.Second
	hedgeDelay              = 250 * time.Millisecond
	maxManagedResponseBytes = 16 << 20
)

// nodes=auto hands node selection to the panel: the Node Filter bound to this
// token, or the plan's default lines when none is saved.
const (
	managedConfigPath  = "/api/v1/managed/flclash/direct"
	managedConfigQuery = "nodes=auto"
)

// The panel tells official clients apart by this header, not by the User-Agent.
const oixClientHeader = "X-oixCloud-Client"

// Clients that ship this core, keyed by the ID the panel knows them by. A panel that does not
// know the header falls back to the first legacy name in the User-Agent, so a new client's
// User-Agent must not contain "oixCloud", which is the iOS app's name there.
var oixClients = map[string]string{
	"openclash": "OpenClash for oixCloud",
	"oixclash":  "oixClash",
}

const defaultClientID = "openclash"

var (
	clientMu sync.RWMutex
	clientID string
)

func SetClient(id string) error {
	id = strings.ToLower(strings.TrimSpace(id))
	if _, ok := oixClients[id]; !ok {
		return fmt.Errorf("unknown oixCloud client %q", id)
	}
	clientMu.Lock()
	clientID = id
	clientMu.Unlock()
	return nil
}

// currentClient falls back to OIX_CLIENT, then to OpenClash, whose builds never set either.
func currentClient() (id, userAgent string) {
	clientMu.RLock()
	id = clientID
	clientMu.RUnlock()
	if id == "" {
		id = strings.ToLower(strings.TrimSpace(os.Getenv("OIX_CLIENT")))
	}
	if _, ok := oixClients[id]; !ok {
		id = defaultClientID
	}
	return id, oixClients[id]
}

type apiResponse struct {
	Ret    int    `json:"ret"`
	Msg    string `json:"msg"`
	Config string `json:"config"`
}

func IsAuthError(err error) bool {
	return errors.Is(err, ErrAuthFailed)
}

// rejectedError is a managed config refusal about the request itself, such as
// a timestamp outside the panel's window after a cold boot. The token may be
// fine, so callers retry and keep what they have instead of signing out.
type rejectedError struct {
	Reason string
}

func (e *rejectedError) clockSkew() bool {
	return strings.HasPrefix(e.Reason, "timestamp_")
}

// Front ends such as the Merlin plugin match "check the device clock".
func (e *rejectedError) Error() string {
	if e.clockSkew() {
		return fmt.Sprintf("managed request rejected: %s (check the device clock)", e.Reason)
	}
	return "managed request rejected: " + e.Reason
}

// Reasons the panel sends in X-Managed-Auth-Error for a request it could not
// accept whatever the token; dedicated_token_required is about the token.
var requestRejections = map[string]bool{
	"timestamp_missing":   true,
	"timestamp_invalid":   true,
	"timestamp_expired":   true,
	"signature_missing":   true,
	"signature_mismatch":  true,
	"age_pubkey_missing":  true,
	"age_pubkey_invalid":  true,
	"server_unconfigured": true,
}

func managedStatusError(resp *http.Response) error {
	if resp.StatusCode == http.StatusForbidden {
		if reason := strings.TrimSpace(resp.Header.Get("X-Managed-Auth-Error")); requestRejections[reason] {
			return &rejectedError{Reason: reason}
		}
	}
	return oixStatusError(resp.StatusCode)
}

func IsConfigError(err error) bool {
	return errors.Is(err, ErrNoToken) || errors.Is(err, ErrNoDomains)
}

func ageKeyFilePath(homeDir string) string {
	return filepath.Join(homeDir, ".oix_age_key")
}

func ageKeyPair() (secretKey, publicKey string) {
	ageKeyInitOnce.Do(func() {
		if ageSecretKey != "" && agePublicKey != "" {
			return
		}
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

// ProviderDirectoryOf resolves the managed provider directory from providers
// that have already been parsed, so callers do not repeat the path scan.
func ProviderDirectoryOf[T interface{ Path() string }](homeDir, preferredPath string, providers map[string]T) string {
	providerPaths := make([]string, 0, len(providers))
	for _, pv := range providers {
		if path := pv.Path(); path != "" {
			providerPaths = append(providerPaths, path)
		}
	}
	return ProviderDirectory(homeDir, preferredPath, providerPaths)
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

	config, err := fetchBest(context.Background(), token, urls)
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
	if config == nil {
		log.Warnln("[oixCloud] ensure failed, no provider found for [%s]", ProviderFile())
		ensureFromDisk(dir, homeDir)
		return false, nil
	}
	ok := saveResult(dir, homeDir, config.data)
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

// Temporary failures are retried well before the next regular update, so a
// router that started before NTP synced or before its WAN came up gets its
// nodes within minutes instead of a day later.
var (
	retryDelays = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute}
	retryEvery  = time.Hour
)

func isTemporary(err error) bool {
	return err != nil && !IsAuthError(err) && !IsConfigError(err) && !errors.Is(err, ErrNoSubscription)
}

func retryDelay(interval time.Duration, failures int) time.Duration {
	delay := interval
	switch {
	case failures <= 0:
	case failures <= len(retryDelays):
		delay = retryDelays[failures-1]
	default:
		delay = retryEvery
	}
	return min(delay, interval)
}

func updateInterval() time.Duration {
	if s := os.Getenv("OIX_UPDATE_INTERVAL"); s != "" {
		const maxIntervalSeconds = int64(^uint64(0)>>1) / int64(time.Second)
		if seconds, err := strconv.ParseInt(s, 10, 64); err == nil && seconds > 0 && seconds <= maxIntervalSeconds {
			return time.Duration(seconds) * time.Second
		}
	}
	return defaultUpdateInterval
}

// runUpdater calls update every interval, and sooner after temporary
// failures, until ctx is done. retrySoon starts with a quick retry.
func runUpdater(ctx context.Context, interval time.Duration, retrySoon bool, update func() error) {
	failures := 0
	if retrySoon {
		failures = 1
	}
	timer := time.NewTimer(retryDelay(interval, failures))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		err := update()
		if ctx.Err() != nil {
			return
		}
		if isTemporary(err) {
			failures++
		} else {
			failures = 0
		}
		timer.Reset(retryDelay(interval, failures))
	}
}

// StartPeriodicUpdate keeps the provider file up to date; lastErr is the
// result of the fetch that preceded it, so a temporary failure is retried soon.
func StartPeriodicUpdate(dir, homeDir string, lastErr error) {
	interval := updateInterval()

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
		runUpdater(ctx, interval, isTemporary(lastErr), func() error {
			err := runPeriodicUpdate(ctx, dir, homeDir)
			if err != nil && ctx.Err() == nil {
				log.Warnln("[oixCloud] periodic update failed: %s", err)
			}
			return err
		})
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
	config, err := fetchBest(ctx, token, urls)
	if err != nil {
		return err
	}
	if config == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !saveResult(dir, homeDir, config.data) {
		return errors.New("save failed")
	}
	log.Infoln("[oixCloud] periodic update saved to %s", filepath.Join(homeDir, dir, ProviderFile()))
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
	ok, err := Ensure(dir, homeDir, true)
	if err == nil && !ok {
		return ErrNoSubscription
	}
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
	tokenMu.Lock()
	defer tokenMu.Unlock()
	if homeDir == "" || loggedOut || loginToken != "" || normalizeToken(os.Getenv("OIX_TOKEN")) != "" {
		return
	}
	path := tokenFilePath(homeDir)
	data, err := readPrivateFile(path)
	if err != nil {
		return
	}
	loginToken = normalizeToken(string(data))
}

func persistToken(homeDir, token string) error {
	if homeDir == "" {
		return errors.New("home dir not set")
	}
	return writePrivateFile(tokenFilePath(homeDir), []byte(token))
}

func Login(token string) (bool, error) {
	accountMu.Lock()
	defer accountMu.Unlock()

	token = normalizeToken(token)
	if token == "" {
		return false, ErrNoToken
	}
	if ProfileMode() {
		return loginProfile(token)
	}
	dir, homeDir := providerPaths()
	if dir == "" {
		return false, errors.New("oix provider not initialized")
	}

	// Validate a candidate account without exposing it to concurrent updates or
	// disturbing the active account when authentication or provider storage fails.
	if ok, err := loginWithToken(dir, homeDir, token); err != nil || !ok {
		return ok, err
	}
	StartPeriodicUpdate(dir, homeDir, nil)
	return true, nil
}

func loginWithToken(dir, homeDir, token string) (bool, error) {
	providerUpdateMu.Lock()
	defer providerUpdateMu.Unlock()

	config, err := fetchBest(context.Background(), token, apiBaseURLs())
	if err != nil || config == nil {
		return false, err
	}
	if !saveResult(dir, homeDir, config.data) {
		return false, errors.New("save failed")
	}
	if err := persistToken(homeDir, token); err != nil {
		log.Warnln("[oixCloud] persist token failed: %s", err)
	}
	SetToken(token)
	oixdns.SetEnsured()
	return true, nil
}

func Logout() {
	accountMu.Lock()
	defer accountMu.Unlock()

	tokenMu.Lock()
	loginToken = ""
	loggedOut = true
	tokenMu.Unlock()
	StopPeriodicUpdate()
	removeProfile()
	dir, homeDir := providerPaths()
	if ProfileMode() {
		// the provider paths are never set in profile mode
		homeDir = C.Path.HomeDir()
	}
	providerUpdateMu.Lock()
	defer providerUpdateMu.Unlock()
	oixdns.ClearEnsured()
	oixdns.ResetManagedDNS()
	if homeDir != "" {
		_ = os.Remove(tokenFilePath(homeDir))
		if dir != "" {
			_ = os.Remove(filepath.Join(homeDir, dir, ProviderFile()))
		}
	}
}

func IsoixProvider(name string) bool {
	return name == ProviderFile()
}

type fetchedConfig struct {
	data  []byte // age-encrypted, as saved to disk
	plain []byte
}

func fetchBest(parent context.Context, token string, urls []string) (*fetchedConfig, error) {
	if len(urls) == 0 {
		return nil, ErrNoDomains
	}
	// Always go through the Once so this goroutine synchronizes with whichever
	// one generated the pair before reading it below.
	ageKeyPair()
	ctx, cancel := context.WithTimeout(parent, totalTimeout)
	defer cancel()
	attempts := make([]func(context.Context) (*fetchedConfig, error), 0, len(urls))
	for i, baseURL := range urls {
		attempts = append(attempts, func(ctx context.Context) (*fetchedConfig, error) {
			if i > 0 {
				timer := time.NewTimer(hedgeDelay)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return reportEmptySubscription(fetchFrom(ctx, token, baseURL))
		})
	}
	return raceConfigReads(ctx, attempts)
}

// reportEmptySubscription turns an empty result into an error so a racing peer
// that may still hold a subscription is awaited instead of being cancelled.
func reportEmptySubscription(config *fetchedConfig, err error) (*fetchedConfig, error) {
	if err == nil && config == nil {
		return nil, ErrNoSubscription
	}
	return config, err
}

// raceConfigReads restores the empty-subscription result once every attempt has
// reported it, while an authentication failure stays authoritative.
func raceConfigReads(ctx context.Context, attempts []func(context.Context) (*fetchedConfig, error)) (*fetchedConfig, error) {
	config, err := mihomoHttp.RaceReads(ctx, attempts, nil)
	if !IsAuthError(err) && errors.Is(err, ErrNoSubscription) {
		return nil, nil
	}
	return config, err
}

type oixHTTPClientContextKey struct{}

func fetchFrom(ctx context.Context, token, baseURL string) (*fetchedConfig, error) {
	ctx, cancel := context.WithTimeout(ctx, totalTimeout)
	defer cancel()
	clients := []*http.Client{oixHTTPClient}
	if inner.GetTunnel() != nil {
		clients = append([]*http.Client{oixRoutedHTTPClient}, clients...)
	}
	return fetchFromClients(ctx, token, baseURL, clients)
}

func fetchFromClients(ctx context.Context, token, baseURL string, clients []*http.Client) (*fetchedConfig, error) {
	attempts := make([]func(context.Context) (*fetchedConfig, error), 0, len(clients))
	for _, client := range clients {
		attempts = append(attempts, func(ctx context.Context) (*fetchedConfig, error) {
			routeCtx := context.WithValue(ctx, oixHTTPClientContextKey{}, client)
			return reportEmptySubscription(fetchFromRoute(routeCtx, token, baseURL))
		})
	}
	return raceConfigReads(ctx, attempts)
}

func fetchFromRoute(ctx context.Context, token, baseURL string) (*fetchedConfig, error) {
	if agePublicKey == "" {
		return nil, errors.New("age key unavailable")
	}
	if AppSecret == "" {
		return nil, errors.New("app secret unavailable")
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)

	sig := sign(ts + "." + agePublicKey)

	url := baseURL + managedConfigPath + "?" + managedConfigQuery

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", mihomoHttp.RedactError(err))
	}
	client, userAgent := currentClient()
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set(oixClientHeader, client)
	req.Header.Set(subscriptionCapabilitiesHeader, subscriptionCapabilities())
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Flclash-Timestamp", ts)
	req.Header.Set("X-Flclash-Signature", sig)
	req.Header.Set("X-Flclash-Age-Pubkey", agePublicKey)

	resp, err := oixHTTPDo(req)
	if err != nil {
		return nil, fmt.Errorf("server request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, managedStatusError(resp)
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
	data, plain, err := decodeArmoredConfig(apiResp.Config)
	if err != nil {
		return nil, err
	}
	return &fetchedConfig{data: data, plain: plain}, nil
}

func decodeJSONResponse(reader io.Reader, maxBytes int64, target any) error {
	limited := &io.LimitedReader{R: reader, N: maxBytes + 1}
	oversized := func() error { return fmt.Errorf("response exceeds %d bytes", maxBytes) }
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(target); err != nil {
		if limited.N == 0 {
			return oversized()
		}
		return err
	}
	var extra struct{}
	err := decoder.Decode(&extra)
	switch {
	case limited.N == 0:
		return oversized()
	case errors.Is(err, io.EOF):
		return nil
	case err == nil:
		return errors.New("response contains multiple JSON values")
	default:
		return fmt.Errorf("invalid trailing response data: %w", err)
	}
}

func apiResponseError(scope string, ret int, msg string) error {
	err := fmt.Errorf("%s rejected (ret=%d): %s", scope, ret, msg)
	if ret == http.StatusUnauthorized || ret == http.StatusForbidden {
		return fmt.Errorf("%w: %w", oixStatusError(ret), err)
	}
	return err
}

func oixStatusError(status int) error {
	err := error(mihomoHttp.StatusError(status))
	if mihomoHttp.IsAuthenticationError(err) {
		return fmt.Errorf("%w: %w", ErrAuthFailed, err)
	}
	return err
}

func decodeArmoredConfig(encoded string) (raw, plain []byte, err error) {
	raw, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("decode config: %w", err)
	}
	if !isAgeArmored(raw) {
		return nil, nil, errors.New("config not encrypted")
	}
	plain, err = age.DecryptBytes(raw, ageSecretKey)
	if err != nil {
		return nil, nil, errors.New("invalid encrypted config")
	}
	var schema struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(plain, &schema); err != nil || schema.Proxies == nil {
		return nil, nil, errors.New("invalid managed provider config")
	}
	return raw, plain, nil
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
	return lookupoixHost(ctx, r.Resolver, r.fallbackForHost(host), func(lookupCtx context.Context, current oixHostResolver) ([]netip.Addr, error) {
		return current.LookupIP(lookupCtx, host)
	})
}

func (r oixFallbackResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return lookupoixHost(ctx, r.Resolver, r.fallbackForHost(host), func(lookupCtx context.Context, current oixHostResolver) ([]netip.Addr, error) {
		return current.LookupIPv4(lookupCtx, host)
	})
}

func (r oixFallbackResolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return lookupoixHost(ctx, r.Resolver, r.fallbackForHost(host), func(lookupCtx context.Context, current oixHostResolver) ([]netip.Addr, error) {
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
	// system is asked only when every server failed, for networks that
	// block outside DNS; a core without its own DNS yet, or the oix
	// subcommand, has nothing else.
	system interface {
		LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	}
}

var oixBootstrapHostResolver oixHostResolver = &oixBootstrapResolver{
	servers: []string{"223.5.5.5:53", "119.29.29.29:53"},
	system:  net.DefaultResolver,
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
	addresses, err := r.lookupServers(ctx, network, host)
	if err == nil || r.system == nil || ctx.Err() != nil {
		return addresses, err
	}
	addresses, systemErr := r.system.LookupNetIP(ctx, network, host)
	if systemErr == nil && len(addresses) > 0 {
		return addresses, nil
	}
	if systemErr == nil {
		systemErr = resolver.ErrIPNotFound
	}
	return nil, errors.Join(err, systemErr)
}

func (r *oixBootstrapResolver) lookupServers(ctx context.Context, network, host string) ([]netip.Addr, error) {
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

func lookupoixHost(ctx context.Context, primary, fallback oixHostResolver, lookup func(context.Context, oixHostResolver) ([]netip.Addr, error)) ([]netip.Addr, error) {
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

func newoixHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			mihomoHttp.StripRedirectCredentials(req.Header, req.URL, via[0].URL)
			return nil
		},
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

func newoixRoutedHTTPClient() *http.Client {
	client := newoixHTTPClient()
	transport := client.Transport.(*http.Transport)
	direct := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if conn, err := inner.HandleTcp(inner.GetTunnel(), address, ""); err == nil {
			return conn, nil
		}
		return direct(ctx, network, address)
	}
	return client
}

// Only the explicitly read-only managed config request may be replayed.
func isoixRead(req *http.Request) bool {
	return req.Method == http.MethodGet && req.URL.Path == managedConfigPath
}

func oixHTTPDo(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	deadline := time.Now().Add(totalTimeout)
	var lastErr error
	retries := 0
	if isoixRead(req) {
		retries = maxRetries
	}
	client := oixHTTPClient
	if route, ok := ctx.Value(oixHTTPClientContextKey{}).(*http.Client); ok {
		client = route
	}
	for i := 0; i <= retries; i++ {
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
		resp, err := client.Do(attempt)
		if err != nil {
			lastErr = mihomoHttp.RedactError(err)
			continue
		}
		if resp.StatusCode >= 500 && retries > 0 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			resp.Body.Close()
			continue
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("request failed")
	}
	return nil, fmt.Errorf("request failed after %d attempts: %w", retries+1, lastErr)
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
	// Exact patterns win over wildcards, then the domain, then the raw pattern.
	slices.SortFunc(patterns, func(a, b string) int {
		domainA, exactA := normalizeManagedDNSPattern(a)
		domainB, exactB := normalizeManagedDNSPattern(b)
		if exactA != exactB {
			if exactA {
				return -1
			}
			return 1
		}
		if domainA != domainB {
			return strings.Compare(domainA, domainB)
		}
		return strings.Compare(strings.ToLower(strings.TrimSpace(a)), strings.ToLower(strings.TrimSpace(b)))
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
