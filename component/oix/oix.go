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
	ApiDomains        string
	ProfileKey        string

	ageSecretKey      string
	agePublicKey      string
	ageKeyInitOnce    sync.Once

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

func ProviderConfig(relPath string) map[string]any {
	ageKeyPair()

	return map[string]any{
		"type":           "file",
		"path":           "./" + relPath,
		"age-secret-key": ageSecretKey,
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
	ok := saveResult(dir, homeDir, result)
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

func IsOixProvider(name string) bool {
	return name == ProviderFile()
}

func CreateProvider(dir, homeDir string, base map[string]any) (P.ProxyProvider, error) {
	name := ProviderFile()
	providerPath := filepath.Join(homeDir, dir, name)
	relPath, _ := filepath.Rel(homeDir, providerPath)

	oixCfg := ProviderConfig(relPath)
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
					base["health-check"] = hcMerged
				}
			}
		}
		for k, v := range oixCfg {
			if _, exists := base[k]; exists && k == "health-check" {
				continue
			}
			base[k] = v
		}
		oixCfg = base
	}

	pd, err := provider.ParseProxyProvider(name, oixCfg, C.Tunnel(tunnel.Tunnel))
	if err != nil {
		log.Warnln("[OixCloud] parse provider error: %s", err)
		return nil, err
	}
	return pd, nil
}

func fetchBest(token string, urls []string) (*Result, error) {
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

func fetchFrom(token, baseURL string) (*Result, error) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	sig := sign(ts + "." + agePublicKey)

	url := baseURL + "/api/v1/managed/flclash/direct"

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request failed")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Flclash-Timestamp", ts)
	req.Header.Set("X-Flclash-Signature", sig)
	req.Header.Set("X-Flclash-Age-Pubkey", agePublicKey)

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

	if err := verifyResponseSignature(ts, apiResp.Config, resp.Header.Get("X-Flclash-Response-Signature")); err != nil {
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

func verifyResponseSignature(timestamp, configB64, headerSig string) error {
	if headerSig != "" {
		expected := sign(timestamp + "." + configB64)
		if !hmac.Equal([]byte(expected), []byte(headerSig)) {
			return fmt.Errorf("response signature mismatch")
		}
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(configB64)
	if err != nil {
		return nil
	}
	if isAgeArmored(raw) {
		return fmt.Errorf("missing response signature")
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

func oixHTTPDo(req *http.Request) (*http.Response, error) {
	oixHTTPOnce.Do(func() {
		oixHTTPClient = &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
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
		if strings.HasPrefix(d, "http://") {
			d = "https://" + strings.TrimPrefix(d, "http://")
		} else if !strings.HasPrefix(d, "https://") {
			d = "https://" + d
		}
		urls = append(urls, d)
	}
	return urls
}
