package oix

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
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

	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/component/age"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

var (
	AppSecret         string
	AgeSecretKey      string
	AgePublicKey      string
	ApiDomains        string
	ProfileKey        string

	flclashBuild      string
	flclashBuildOnce  sync.Once

	oixQueryParams    string
	oixProviderName   string

	periodicCancel    context.CancelFunc
	periodicDir       string
	periodicHome      string

	oixHTTPOnce       sync.Once
	oixHTTPClient     *http.Client
)

var (
	ErrAuthFailed = errors.New("authentication failed")
	ErrNoToken    = errors.New("OIX_TOKEN not set")
	ErrNoDomains  = errors.New("no API domains configured")
)

const (
	defaultProviderFile = "oixCloud"
	defaultQueryParams  = "smart"
	defaultProviderDir  = "proxy_providers"
)

const (
	maxRetries   = 2
	totalTimeout = 30 * time.Second
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

type managedAPIResponse struct {
	Ret   int    `json:"ret"`
	Msg   string `json:"msg"`
	Name  string `json:"name"`
	Smart string `json:"smart"`
}

func IsAuthError(err error) bool {
	return errors.Is(err, ErrAuthFailed)
}

func IsConfigError(err error) bool {
	return errors.Is(err, ErrNoToken) || errors.Is(err, ErrNoDomains)
}

func GetAgeSecretKey() string {
	return AgeSecretKey
}

func ProviderConfig(relPath string) map[string]any {
	return map[string]any{
		"type":           "file",
		"path":           "./" + relPath,
		"age-secret-key": AgeSecretKey,
		"health-check": map[string]any{
			"enable":   true,
			"url":      "https://www.gstatic.com/generate_204",
			"interval": 300,
		},
	}
}

func Ensure(dir, homeDir string, providerExists bool) (bool, error) {
	token := os.Getenv("OIX_TOKEN")
	if token == "" {
		return false, fmt.Errorf("%w", ErrNoToken)
	}
	urls := apiBaseURLs()
	if len(urls) == 0 {
		return false, fmt.Errorf("%w", ErrNoDomains)
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
	ok, _ := saveResult(dir, homeDir, result)
	if !ok {
		return false, errors.New("save failed")
	}
	if providerExists {
		log.Infoln("[OixCloud] provider [%s] already exists, file updated", ProviderFile())
	} else {
		log.Infoln("[OixCloud] provider fetched successfully: [%s]", ProviderFile())
	}
	return true, nil
}

func SetQueryParams(params string) {
	oixQueryParams = params
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
				token := os.Getenv("OIX_TOKEN")
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
				ok, _ := saveResult(dir, homeDir, result)
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

func IsOixProvider(name string) bool {
	return name == ProviderFile()
}

func CreateProvider(dir, homeDir string, base map[string]any) (P.ProxyProvider, error) {
	name := ProviderFile()
	providerPath := filepath.Join(homeDir, dir, name)
	relPath, _ := filepath.Rel(homeDir, providerPath)

	oixCfg := ProviderConfig(relPath)
	if base != nil {
		merged := make(map[string]any, len(base)+len(oixCfg))
		for k, v := range base {
			merged[k] = v
		}
		for k, v := range oixCfg {
			merged[k] = v
		}
		oixCfg = merged
	}

	pd, err := provider.ParseProxyProvider(name, oixCfg, C.Tunnel(tunnel.Tunnel))
	if err != nil {
		log.Warnln("[OixCloud] parse provider error: %s", err)
		return nil, err
	}
	return pd, nil
}

func Fetch() (*Result, error) {
	token := os.Getenv("OIX_TOKEN")
	if token == "" {
		return nil, nil
	}
	urls := apiBaseURLs()
	if len(urls) == 0 {
		return nil, nil
	}
	return fetchBest(token, urls)
}

func fetchBest(token string, urls []string) (*Result, error) {
	flclashBuildOnce.Do(func() {
		flclashBuild = fetchBuildVersion(urls)
	})

	result, err := fetchManaged(token, urls)
	if err == nil && result != nil && (len(result.Config) > 0 || len(result.Provider) > 0) {
		return result, nil
	}
	if err != nil && !IsAuthError(err) {
		log.Warnln("[OixCloud] SUB API failed, fallback to Direct API")
	}

	var lastErr error
	for _, baseURL := range urls {
		result, err := fetchFrom(token, baseURL)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func fetchManaged(token string, urls []string) (*Result, error) {
	if ProfileKey == "" {
		return nil, fmt.Errorf("profile key not configured")
	}
	var lastErr error
	for _, baseURL := range urls {
		result, err := fetchManagedFrom(token, baseURL)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func fetchManagedFrom(token, baseURL string) (*Result, error) {
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/managed/clash", bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, fmt.Errorf("create managed request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	setOixHeaders(req, token)

	resp, err := oixHTTPDo(req)
	if err != nil {
		return nil, fmt.Errorf("server request failed")
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

	var mResp managedAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&mResp); err != nil {
		return nil, fmt.Errorf("decode managed response: %w", err)
	}

	if mResp.Smart == "" {
		return nil, fmt.Errorf("managed API: empty sub URL")
	}

	downloadURL := strings.Replace(mResp.Smart, "clash=", "flclash=", 1)
	if idx := strings.Index(downloadURL, "flclash="); idx != -1 {
		start := idx + len("flclash=")
		origValue := downloadURL[start:]
		ext := ""
		if dot := strings.LastIndex(origValue, "."); dot != -1 {
			ext = origValue[dot:]
		}
		downloadURL = downloadURL[:start] + url.QueryEscape(queryParams()) + ext
	}

	req2, err := http.NewRequest(http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create download request: %w", err)
	}
	setOixHeaders(req2, token)

	resp2, err := oixHTTPDo(req2)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp2.Body, 1024))
		err := fmt.Errorf("download: HTTP %d: %s", resp2.StatusCode, string(body))
		if resp2.StatusCode == 401 || resp2.StatusCode == 403 {
			err = fmt.Errorf("%w: %w", ErrAuthFailed, err)
		}
		return nil, err
	}

	encrypted, err := io.ReadAll(resp2.Body)
	if err != nil {
		return nil, fmt.Errorf("read download: %w", err)
	}

	plaintext, err := decryptFlClash(encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return &Result{Config: plaintext}, nil
}

func fetchFrom(token, baseURL string) (*Result, error) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := sign(ts)

	url := baseURL + "/api/v1/managed/flclash/direct"

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request failed")
	}
	setOixHeaders(req, token)
	req.Header.Set("X-Flclash-Timestamp", ts)
	req.Header.Set("X-Flclash-Signature", sig)

	resp, err := oixHTTPDo(req)
	if err != nil {
		return nil, fmt.Errorf("server request failed")
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

	result := &Result{}

	if apiResp.Config != "" {
		config, err := base64.StdEncoding.DecodeString(apiResp.Config)
		if err != nil {
			return nil, fmt.Errorf("decode config: %w", err)
		}
		result.Config = config
	}

	if apiResp.Provider != "" {
		data, err := base64.StdEncoding.DecodeString(apiResp.Provider)
		if err != nil {
			return nil, fmt.Errorf("decode provider: %w", err)
		}
		result.Provider = data
	}

	return result, nil
}

func sign(timestamp string) string {
	if AppSecret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(AppSecret))
	mac.Write([]byte(timestamp))
	return hex.EncodeToString(mac.Sum(nil))
}

func decryptFlClash(data []byte) ([]byte, error) {
	if len(data) < 4+1+12+16 {
		return nil, fmt.Errorf("invalid encrypted structure size")
	}
	if string(data[:4]) != "FLEN" || data[4] != 0x02 {
		return nil, fmt.Errorf("magic or version mismatch")
	}
	iv := data[5 : 5+12]
	ciphertext := data[5+12:]

	if ProfileKey == "" {
		return nil, fmt.Errorf("profile key is not injected")
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
			return nil, fmt.Errorf("invalid character found in decrypted text")
		}
	}

	return plaintext, nil
}

func fetchBuildVersion(urls []string) string {
	for _, baseURL := range urls {
		req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/version/get", nil)
		if err != nil {
			continue
		}
		resp, err := oixHTTPDo(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			continue
		}
		var result struct {
			Ret  int    `json:"ret"`
			Msg  string `json:"msg"`
			Data struct {
				Version string `json:"version"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()
		if result.Data.Version != "" {
			log.Infoln("[OixCloud] build version: %s", result.Data.Version)
			return result.Data.Version
		}
	}
	return ""
}

func setOixHeaders(req *http.Request, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
	if flclashBuild != "" {
		req.Header.Set("X-Flclash-Build", flclashBuild)
	}
}

func oixHTTPDo(req *http.Request) (*http.Response, error) {
	oixHTTPOnce.Do(func() {
		oixHTTPClient = &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, addr)
				},
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       30 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}
	})

	deadline := time.Now().Add(totalTimeout)
	for i := 0; i <= maxRetries; i++ {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("retry timeout")
		}
		if i > 0 {
			time.Sleep(time.Duration(i) * time.Second)
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

func saveResult(dir, homeDir string, result *Result) (bool, string) {
	p := filepath.Join(homeDir, dir, ProviderFile())

	raw := result.Provider
	if len(raw) == 0 {
		raw = result.Config
	}

	// Encrypt with age public key if configured
	if AgePublicKey != "" {
		encrypted, err := age.EncryptBytes(raw, AgePublicKey)
		if err != nil {
			log.Warnln("[OixCloud] age encrypt: %s", err)
			return false, ""
		}
		raw = encrypted
	}

	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		log.Warnln("[OixCloud] write file %s: %s", p, err)
		return false, ""
	}

	return true, p
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

func queryParams() string {
	if oixQueryParams != "" {
		return oixQueryParams
	}
	if params := os.Getenv("OIX_QUERY_PARAMS"); params != "" {
		return params
	}
	return defaultQueryParams
}

func apiBaseURLs() []string {
	if ApiDomains == "" {
		return nil
	}
	domains := strings.Split(ApiDomains, ",")
	urls := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if !strings.HasPrefix(d, "https://") && !strings.HasPrefix(d, "http://") {
			d = "https://" + d
		}
		urls = append(urls, d)
	}
	return urls
}
