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
	"net/url"
	"os"
	"path/filepath"
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

	periodicCancel context.CancelFunc
	periodicDone   chan struct{}
	periodicDir    string
	periodicHome   string
	periodicMu     sync.RWMutex

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
	return os.Getenv("OIX_TOKEN")
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
			if err := os.Chmod(keyPath, 0o600); err != nil && !os.IsNotExist(err) {
				log.Warnln("[oixCloud] secure age key failed: %s", err)
			}
			if data, err := os.ReadFile(keyPath); err == nil {
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
			if err := os.WriteFile(ageKeyFilePath(homeDir), []byte(sk), 0o600); err != nil {
				log.Warnln("[oixCloud] persist age key failed: %s", err)
			} else if err := os.Chmod(ageKeyFilePath(homeDir), 0o600); err != nil {
				log.Warnln("[oixCloud] secure age key failed: %s", err)
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

func Ensure(dir, homeDir string, providerExists bool) (bool, error) {
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
	oixProviderName = name
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

func StartPeriodicUpdate(dir, homeDir string) {
	interval := 3600 * time.Second
	if s := os.Getenv("OIX_UPDATE_INTERVAL"); s != "" {
		if d, err := strconv.Atoi(s); err == nil && d > 0 {
			interval = time.Duration(d) * time.Second
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
				token := getToken()
				if token == "" {
					continue
				}
				urls := apiBaseURLs()
				if len(urls) == 0 {
					continue
				}
				config, err := fetchBest(ctx, token, urls, homeDir)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Warnln("[oixCloud] periodic update failed: %s", err)
					continue
				}
				if len(config) == 0 {
					continue
				}
				if ctx.Err() != nil {
					return
				}
				ok := saveResult(dir, homeDir, config)
				if ok {
					log.Infoln("[oixCloud] periodic update saved to %s", filepath.Join(homeDir, dir, ProviderFile()))
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	periodicMu.Unlock()
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
	data, err := os.ReadFile(tokenFilePath(homeDir))
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
	return os.WriteFile(tokenFilePath(homeDir), []byte(token), 0o600)
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
	oixdns.ClearEnsured()
	oixdns.ResetManagedDNS()
	StopPeriodicUpdate()
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

	var lastErr error
	var authErr error
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
		lastErr = o.err
		if errors.Is(o.err, ErrAuthFailed) {
			authErr = o.err
		}
	}
	if hadEmpty {
		return nil, nil
	}
	if authErr != nil {
		return nil, authErr
	}
	if lastErr == nil {
		lastErr = ErrNoDomains
	}
	return nil, lastErr
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
		if resp.StatusCode == 401 {
			err = fmt.Errorf("%w: %w", ErrAuthFailed, err)
		}
		return nil, err
	}

	var apiResp apiResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxManagedResponseBytes)).Decode(&apiResp); err != nil {
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAccountResponseBytes)).Decode(&apiResp); err != nil {
		return planIdentity{}, fmt.Errorf("decode account response: %w", err)
	}
	return planIdentityFromResponse(apiResp)
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

func newOixHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr, dialer.WithResolver(resolver.DirectHostResolver))
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
	for i := 0; i <= maxRetries; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, errors.New("retry timeout")
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
		resp, err := oixHTTPClient.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode >= 500 {
			resp.Body.Close()
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("request failed after %d retries", maxRetries+1)
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
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		log.Warnln("[oixCloud] write file %s: %s", p, err)
		return false
	}
	if err := os.Chmod(p, 0o600); err != nil {
		log.Warnln("[oixCloud] secure file %s: %s", p, err)
		return false
	}
	applyManagedDNSConfig(plain)

	return true
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
	oixdns.ResetManagedDNS()
	target := oixdns.ManagedNodesDomain()
	for pattern, value := range config.DNS.NameServerPolicy {
		domain := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(pattern), "+."))
		domain = strings.TrimPrefix(strings.TrimSuffix(domain, "."), ".")
		if domain != target {
			continue
		}
		for _, nameserver := range managedNameServers(value) {
			if addr, ok := managedDNSAddress(nameserver); ok {
				oixdns.ConfigureManagedDNS(domain, addr)
				return
			}
		}
	}
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
	if oixProviderName != "" {
		return oixProviderName
	}
	if name := os.Getenv("OIX_PROVIDER_NAME"); name != "" {
		return name
	}
	return defaultProviderFile
}

func apiBaseURLs() []string {
	domains := strings.Split(ApiDomains, ",")
	domains = append(domains, strings.Split(SpareApiDomain, ",")...)
	urls := make([]string, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, "http://") {
			d = "https://" + strings.TrimPrefix(d, "http://")
		} else if !strings.HasPrefix(d, "https://") {
			d = "https://" + d
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		urls = append(urls, d)
	}
	return urls
}
