package oix

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/age"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/oix/oixdns"
	"github.com/metacubex/mihomo/log"
)

var (
	AppSecret      string
	ApiDomains     string
	SpareApiDomain string
	ProfileKey     string

	ageSecretKey   string
	agePublicKey   string
	ageKeyInitOnce sync.Once

	oixProviderName string

	periodicCancel context.CancelFunc
	periodicDir    string
	periodicHome   string

	oixHTTPOnce   sync.Once
	oixHTTPClient *http.Client
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
	maxRetries   = 2
	totalTimeout = 30 * time.Second
	hedgeDelay   = 250 * time.Millisecond
)

type Result struct {
	Config   []byte
	Provider []byte
}

type apiResponse struct {
	Ret      int    `json:"ret"`
	Msg      string `json:"msg"`
	Config   string `json:"config"`
	Provider string `json:"provider"`
}

func IsAuthError(err error) bool {
	return errors.Is(err, ErrAuthFailed)
}

func IsConfigError(err error) bool {
	return errors.Is(err, ErrNoToken) || errors.Is(err, ErrNoDomains)
}

func ageKeyPair() (secretKey, publicKey string) {
	ageKeyInitOnce.Do(func() {
		sk, pk, err := age.GenX25519KeyPair()
		if err != nil {
			log.Warnln("[OixCloud] failed to generate age key pair: %s", err)
			return
		}
		ageSecretKey = sk
		agePublicKey = pk
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
		return false, ErrNoToken
	}
	urls := apiBaseURLs()
	if len(urls) == 0 {
		return false, ErrNoDomains
	}

	log.Infoln("[OixCloud] fetching provider...")

	result, err := fetchBest(token, urls)
	if err != nil {
		if IsAuthError(err) {
			log.Warnln("[OixCloud] auth failed, provider [%s] removed", ProviderFile())
		} else {
			log.Warnln("[OixCloud] config fetch failed")
		}
		return false, err
	}
	if result == nil || (len(result.Config) == 0 && len(result.Provider) == 0) {
		log.Warnln("[OixCloud] ensure failed, no provider found for [%s]", ProviderFile())
		return false, nil
	}
	ok := saveResult(dir, homeDir, result)
	if !ok {
		return false, errors.New("save failed")
	}
	oixdns.SetEnsured()
	if providerExists {
		log.Infoln("[OixCloud] provider [%s] already exists, file updated", ProviderFile())
	} else {
		log.Infoln("[OixCloud] provider fetched successfully: [%s]", ProviderFile())
	}
	return true, nil
}

func SetProviderName(name string) {
	oixProviderName = name
}

func StartPeriodicUpdate(dir, homeDir string) {
	StopPeriodicUpdate()

	periodicDir = dir
	periodicHome = homeDir

	interval := 3600 * time.Second
	if s := os.Getenv("OIX_UPDATE_INTERVAL"); s != "" {
		if d, err := strconv.Atoi(s); err == nil && d > 0 {
			interval = time.Duration(d) * time.Second
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	periodicCancel = cancel

	go func() {
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
				result, err := fetchBest(token, urls)
				if err != nil {
					log.Warnln("[OixCloud] periodic update failed: %s", err)
					continue
				}
				if result == nil || (len(result.Config) == 0 && len(result.Provider) == 0) {
					continue
				}
				ok := saveResult(dir, homeDir, result)
				if ok {
					log.Infoln("[OixCloud] periodic update saved to %s", filepath.Join(homeDir, dir, ProviderFile()))
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func StopPeriodicUpdate() {
	if periodicCancel != nil {
		periodicCancel()
		periodicCancel = nil
	}
}

func ForceUpdate() error {
	if periodicDir == "" {
		return errors.New("periodic update not started")
	}
	_, err := Ensure(periodicDir, periodicHome, true)
	return err
}

func SetProviderPaths(dir, homeDir string) {
	periodicDir = dir
	periodicHome = homeDir
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
	if periodicDir == "" {
		return false, errors.New("oix provider not initialized")
	}
	prev := CurrentToken()
	SetToken(token)
	ok, err := Ensure(periodicDir, periodicHome, true)
	if err != nil || !ok {
		SetToken(prev)
		return ok, err
	}
	if err := persistToken(periodicHome, token); err != nil {
		log.Warnln("[OixCloud] persist token failed: %s", err)
	}
	StartPeriodicUpdate(periodicDir, periodicHome)
	return true, nil
}

func Logout() {
	SetToken("")
	if periodicHome != "" {
		_ = os.Remove(tokenFilePath(periodicHome))
		if periodicDir != "" {
			_ = os.Remove(filepath.Join(periodicHome, periodicDir, ProviderFile()))
		}
	}
	StopPeriodicUpdate()
}

func IsOixProvider(name string) bool {
	return name == ProviderFile()
}

func fetchBest(token string, urls []string) (*Result, error) {
	if len(urls) == 0 {
		return nil, ErrNoDomains
	}
	if len(urls) == 1 {
		return fetchFrom(context.Background(), token, urls[0])
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type outcome struct {
		result *Result
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
			result, err := fetchFrom(ctx, token, baseURL)
			results <- outcome{result, err}
		}(i, baseURL)
	}

	var lastErr error
	var authErr error
	var emptySeen bool
	for range urls {
		o := <-results
		if o.err == nil && hasResult(o.result) {
			cancel()
			return o.result, nil
		}
		if o.err != nil {
			lastErr = o.err
			if errors.Is(o.err, ErrAuthFailed) && authErr == nil {
				authErr = o.err
			}
		} else {
			emptySeen = true
		}
	}
	if authErr != nil {
		return nil, authErr
	}
	if lastErr != nil {
		return nil, lastErr
	}
	if emptySeen {
		return &Result{}, nil
	}
	return nil, ErrNoDomains
}

func fetchFrom(ctx context.Context, token, baseURL string) (*Result, error) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	sig := sign(ts + "." + agePublicKey)

	url := baseURL + "/api/v1/managed/flclash/direct"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.New("create request failed")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Flclash-Timestamp", ts)
	req.Header.Set("X-Flclash-Signature", sig)
	req.Header.Set("X-Flclash-Age-Pubkey", agePublicKey)

	resp, err := oixHTTPDo(req)
	if err != nil {
		return nil, errors.New("server request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		err := fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			err = fmt.Errorf("%w: %w", ErrAuthFailed, err)
		}
		return nil, err
	}

	var apiResp apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if apiResp.Ret != 0 {
		err := fmt.Errorf("API ret %d: %s", apiResp.Ret, apiResp.Msg)
		if apiResp.Ret == http.StatusUnauthorized || apiResp.Ret == http.StatusForbidden {
			err = fmt.Errorf("%w: %w", ErrAuthFailed, err)
		}
		return nil, err
	}

	if err := verifyResponseSignature(ts, apiResp.Config, apiResp.Provider, resp.Header.Get("X-Flclash-Response-Signature")); err != nil {
		return nil, err
	}

	result := &Result{}

	if apiResp.Config != "" {
		result.Config, err = decodeAndDecrypt(apiResp.Config, "config", agePublicKey)
		if err != nil {
			return nil, err
		}
	}

	if apiResp.Provider != "" {
		result.Provider, err = decodeAndDecrypt(apiResp.Provider, "provider", agePublicKey)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func hasResult(result *Result) bool {
	return result != nil && (len(result.Config) > 0 || len(result.Provider) > 0)
}

func decodeAndDecrypt(encoded, label, agePublicKey string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", label, err)
	}
	plaintext, err := decryptConfigPayload(raw, agePublicKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", label, err)
	}
	return plaintext, nil
}

func decryptConfigPayload(data []byte, agePublicKey string) ([]byte, error) {
	if isAgeArmored(data) {
		return data, nil
	}
	plaintext, err := decryptFlClashIfNeeded(data)
	if err != nil {
		return nil, err
	}
	return age.EncryptBytes(plaintext, agePublicKey)
}

func sign(timestamp string) string {
	if AppSecret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(AppSecret))
	mac.Write([]byte(timestamp))
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyResponseSignature(timestamp, configB64, providerB64, headerSig string) error {
	if headerSig != "" {
		payload := timestamp + "." + configB64
		if providerB64 != "" {
			payload += "." + providerB64
		}
		expected := sign(payload)
		if !hmac.Equal([]byte(expected), []byte(headerSig)) {
			return errors.New("response signature mismatch")
		}
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(configB64)
	if err != nil {
		return nil
	}
	if isAgeArmored(raw) {
		return errors.New("missing response signature")
	}
	raw, err = base64.StdEncoding.DecodeString(providerB64)
	if err != nil {
		return nil
	}
	if isAgeArmored(raw) {
		return errors.New("missing response signature")
	}
	return nil
}

func isAgeArmored(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("-----BEGIN AGE ENCRYPTED FILE-----"))
}

func isFlClashEncrypted(data []byte) bool {
	return len(data) >= 5 && string(data[:4]) == "FLEN" && data[4] == 0x02
}

func decryptFlClashIfNeeded(data []byte) ([]byte, error) {
	if !isFlClashEncrypted(data) {
		return data, nil
	}
	return decryptFlClash(data)
}

func decryptFlClash(data []byte) ([]byte, error) {
	if len(data) < 4+1+12+16 {
		return nil, errors.New("invalid encrypted structure size")
	}
	if string(data[:4]) != "FLEN" || data[4] != 0x02 {
		return nil, errors.New("magic or version mismatch")
	}
	iv := data[5 : 5+12]
	ciphertext := data[5+12:]

	if ProfileKey == "" {
		return nil, errors.New("profile key is not injected")
	}
	hash := sha256.Sum256([]byte(ProfileKey))

	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(plaintext); i++ {
		if plaintext[i] < 32 && plaintext[i] != '\n' && plaintext[i] != '\r' && plaintext[i] != '\t' {
			return nil, errors.New("invalid character found in decrypted text")
		}
	}

	return plaintext, nil
}

func oixHTTPDo(req *http.Request) (*http.Response, error) {
	oixHTTPOnce.Do(func() {
		oixHTTPClient = &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				Proxy: nil,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, addr)
				},
				TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       30 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}
	})

	ctx := req.Context()
	deadlineCtx, cancel := context.WithTimeout(ctx, totalTimeout)
	responseReturned := false
	defer func() {
		if !responseReturned {
			cancel()
		}
	}()
	req = req.WithContext(deadlineCtx)
	ctx = deadlineCtx
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
		resp.Body = &cancelOnCloseReadCloser{
			ReadCloser: resp.Body,
			cancel:     cancel,
		}
		responseReturned = true
		return resp, nil
	}
	return nil, fmt.Errorf("request failed after %d retries", maxRetries+1)
}

type cancelOnCloseReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (r *cancelOnCloseReadCloser) Close() error {
	err := r.ReadCloser.Close()
	r.cancel()
	return err
}

func saveResult(dir, homeDir string, result *Result) bool {
	p := filepath.Join(homeDir, dir, ProviderFile())

	raw := result.Provider
	if len(raw) == 0 {
		raw = result.Config
	}

	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		log.Warnln("[OixCloud] write file %s: %s", p, err)
		return false
	}

	return true
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
