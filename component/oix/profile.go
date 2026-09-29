package oix

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/age"
	"github.com/metacubex/mihomo/component/oix/oixdns"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"gopkg.in/yaml.v3"
)

// Profile mode runs the panel's managed config as the whole configuration, as
// FlClash does: proxies, groups, rules and DNS come from the panel, and the
// local config file only overrides what the device needs, such as listeners
// and the controller. The managed config stays age-encrypted on disk and is
// decrypted in memory only.
const (
	profileFileName = ".oix_profile"
	// A test run followed by the real start must not fetch twice.
	profileFreshness = 10 * time.Minute
)

// errProfileStale reports a refresh that fell back to the saved copy; it is
// temporary, so the updater retries soon.
var errProfileStale = errors.New("the panel could not be reached, the saved profile stays in use")

var (
	profileMode   atomic.Bool
	profileMu     sync.Mutex
	profileDigest [sha256.Size]byte
	// profileRetry records that the profile in use is a saved copy kept after a
	// temporary failure.
	profileRetry atomic.Bool

	profileUpdaterMu sync.Mutex
	profileCancel    context.CancelFunc
	profileDone      chan struct{}
	profileReloader  func()
)

func SetProfileMode(on bool) { profileMode.Store(on) }

func ProfileMode() bool { return profileMode.Load() }

// SetProfileReloader registers how to re-apply the configuration after a
// periodic update changed the managed config.
func SetProfileReloader(reload func()) {
	profileUpdaterMu.Lock()
	profileReloader = reload
	profileUpdaterMu.Unlock()
}

func profilePath() string {
	return filepath.Join(C.Path.HomeDir(), profileFileName)
}

// ComposeProfile returns the managed config with the local overrides applied.
func ComposeProfile(overlay []byte) ([]byte, error) {
	plain, err := loadProfile(context.Background(), false)
	if err != nil {
		return nil, err
	}
	return mergeProfile(plain, overlay)
}

// loadProfile uses a copy saved within profileFreshness unless forced, and
// falls back to any saved copy when the panel cannot be reached. The panel's
// verdict on the token is final.
func loadProfile(ctx context.Context, force bool) ([]byte, error) {
	profileMu.Lock()
	defer profileMu.Unlock()

	LoadPersistedToken(C.Path.HomeDir())
	token := getToken()
	if token == "" {
		oixdns.ClearEnsured()
		return nil, ErrNoToken
	}
	path := profilePath()
	if !force {
		if plain, ok := readProfile(path, profileFreshness); ok {
			return plain, nil
		}
	}
	urls := apiBaseURLs()
	if len(urls) == 0 {
		return nil, ErrNoDomains
	}
	config, err := fetchBest(ctx, token, urls)
	if err == nil && config == nil {
		err = ErrNoSubscription
	}
	if err != nil {
		if IsAuthError(err) || errors.Is(err, ErrNoSubscription) {
			oixdns.ClearEnsured()
			return nil, err
		}
		if plain, ok := readProfile(path, 0); ok {
			log.Warnln("[oixCloud] profile fetch failed, using the saved copy: %s", err)
			profileRetry.Store(true)
			return plain, nil
		}
		return nil, err
	}
	profileRetry.Store(false)
	plain, err := age.DecryptBytes(config.data, ageSecretKey)
	if err != nil {
		return nil, errors.New("invalid encrypted profile")
	}
	if err := writePrivateFile(path, config.data); err != nil {
		log.Warnln("[oixCloud] save profile failed: %s", err)
	}
	useProfile(plain)
	return plain, nil
}

// readProfile returns the saved profile if it decrypts and, when maxAge is
// set, was saved within maxAge.
func readProfile(path string, maxAge time.Duration) ([]byte, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	if maxAge > 0 && time.Since(info.ModTime()) > maxAge {
		return nil, false
	}
	raw, err := readPrivateFile(path)
	if err != nil || !isAgeArmored(raw) {
		return nil, false
	}
	secretKey, _ := ageKeyPair()
	if secretKey == "" {
		return nil, false
	}
	plain, err := age.DecryptBytes(raw, secretKey)
	if err != nil {
		return nil, false
	}
	useProfile(plain)
	return plain, true
}

func useProfile(plain []byte) {
	profileDigest = sha256.Sum256(plain)
	applyManagedDNSConfig(plain)
	oixdns.SetEnsured()
}

func mergeProfile(managed, overlay []byte) ([]byte, error) {
	var config map[string]any
	if err := yaml.Unmarshal(managed, &config); err != nil || config == nil {
		return nil, errors.New("managed profile is not a YAML mapping")
	}
	var local map[string]any
	if err := yaml.Unmarshal(overlay, &local); err != nil {
		return nil, fmt.Errorf("local config: %w", err)
	}
	mergeMaps(config, local)
	return yaml.Marshal(config)
}

// mergeMaps merges mappings key by key; any other value replaces the managed one.
func mergeMaps(dst, src map[string]any) {
	for key, value := range src {
		if srcMap, ok := value.(map[string]any); ok {
			if dstMap, ok := dst[key].(map[string]any); ok {
				mergeMaps(dstMap, srcMap)
				continue
			}
		}
		dst[key] = value
	}
}

// refreshProfile fetches the managed config and reports whether it changed.
func refreshProfile(ctx context.Context) (bool, error) {
	profileMu.Lock()
	previous := profileDigest
	profileMu.Unlock()
	if _, err := loadProfile(ctx, true); err != nil {
		return false, err
	}
	if profileRetry.Load() {
		return false, errProfileStale
	}
	profileMu.Lock()
	defer profileMu.Unlock()
	return !bytes.Equal(previous[:], profileDigest[:]), nil
}

// StartProfileUpdates keeps the running configuration in step with the panel.
// It survives reloads, which it triggers itself.
func StartProfileUpdates() {
	profileUpdaterMu.Lock()
	defer profileUpdaterMu.Unlock()
	if profileCancel != nil {
		return
	}
	interval := updateInterval()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	profileCancel, profileDone = cancel, done
	failures := 0
	if profileRetry.Load() {
		failures = 1
	}
	go func() {
		defer close(done)
		timer := time.NewTimer(retryDelay(interval, failures))
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				changed, err := refreshProfile(ctx)
				if isTemporary(err) {
					failures++
				} else {
					failures = 0
				}
				timer.Reset(retryDelay(interval, failures))
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					// loadProfile already logged the fallback itself
					if !errors.Is(err, errProfileStale) {
						log.Warnln("[oixCloud] profile update failed: %s", err)
					}
					continue
				}
				if !changed {
					continue
				}
				profileUpdaterMu.Lock()
				reload := profileReloader
				profileUpdaterMu.Unlock()
				if reload != nil {
					log.Infoln("[oixCloud] profile changed, reloading")
					go reload()
				}
			}
		}
	}()
}

func StopProfileUpdates() {
	profileUpdaterMu.Lock()
	cancel, done := profileCancel, profileDone
	profileCancel, profileDone = nil, nil
	profileUpdaterMu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// loginProfile validates a candidate token by fetching its profile and only
// then replaces the active account.
func loginProfile(token string) (bool, error) {
	profileMu.Lock()
	defer profileMu.Unlock()

	config, err := fetchBest(context.Background(), token, apiBaseURLs())
	if err != nil || config == nil {
		return false, err
	}
	plain, err := age.DecryptBytes(config.data, ageSecretKey)
	if err != nil {
		return false, errors.New("invalid encrypted profile")
	}
	homeDir := C.Path.HomeDir()
	if err := writePrivateFile(profilePath(), config.data); err != nil {
		return false, err
	}
	if err := persistToken(homeDir, token); err != nil {
		log.Warnln("[oixCloud] persist token failed: %s", err)
	}
	SetToken(token)
	useProfile(plain)
	profileRetry.Store(false)
	return true, nil
}

func removeProfile() {
	StopProfileUpdates()
	profileMu.Lock()
	defer profileMu.Unlock()
	profileDigest = [sha256.Size]byte{}
	profileRetry.Store(false)
	_ = os.Remove(profilePath())
}
