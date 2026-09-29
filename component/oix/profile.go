package oix

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	// temporary failure, so the updater starts with a quick retry.
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
// After an explicit logout the local config runs alone.
func ComposeProfile(overlay []byte) ([]byte, error) {
	plain, stale, err := loadProfile(context.Background(), false)
	if errors.Is(err, ErrNoToken) && signedOut() {
		log.Infoln("[oixCloud] signed out, running the local config only")
		return overlay, nil
	}
	if err != nil {
		return nil, err
	}
	profileRetry.Store(stale)
	return mergeProfile(plain, overlay)
}

// loadProfile uses a copy saved within profileFreshness unless forced, and
// falls back to any saved copy, reported as stale, when the panel cannot be
// reached. The panel's verdict on the token is final.
func loadProfile(ctx context.Context, force bool) (plain []byte, stale bool, err error) {
	profileMu.Lock()
	defer profileMu.Unlock()

	LoadPersistedToken(C.Path.HomeDir())
	token := getToken()
	if token == "" {
		oixdns.ClearEnsured()
		return nil, false, ErrNoToken
	}
	path := profilePath()
	if !force {
		if plain, ok := readProfile(path, token, profileFreshness); ok {
			return plain, false, nil
		}
	}
	urls := apiBaseURLs()
	if len(urls) == 0 {
		return nil, false, ErrNoDomains
	}
	config, err := fetchBest(ctx, token, urls)
	if err == nil && config == nil {
		err = ErrNoSubscription
	}
	if err != nil {
		if IsAuthError(err) || errors.Is(err, ErrNoSubscription) {
			oixdns.ClearEnsured()
			return nil, false, err
		}
		if plain, ok := readProfile(path, token, 0); ok {
			log.Warnln("[oixCloud] profile fetch failed, using the saved copy: %s", err)
			return plain, true, nil
		}
		return nil, false, err
	}
	if err := saveProfile(path, token, config.data); err != nil {
		log.Warnln("[oixCloud] save profile failed: %s", err)
	}
	useProfile(config.plain)
	return config.plain, false, nil
}

// The saved profile starts with a digest of the token it was fetched with, so
// a copy is never used for another account.
func profileHeader(token string) []byte {
	sum := sha256.Sum256([]byte("oixCloud profile\x00" + token))
	return []byte("oix-profile-owner: " + hex.EncodeToString(sum[:16]) + "\n")
}

func saveProfile(path, token string, data []byte) error {
	return writePrivateFile(path, append(profileHeader(token), data...))
}

func readProfile(path, token string, maxAge time.Duration) ([]byte, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	// a clock set back after the save must not keep the copy fresh
	if elapsed := time.Since(info.ModTime()); maxAge > 0 && (elapsed < 0 || elapsed > maxAge) {
		return nil, false
	}
	raw, err := readPrivateFile(path)
	if err != nil {
		return nil, false
	}
	data, ok := bytes.CutPrefix(raw, profileHeader(token))
	if !ok || !isAgeArmored(data) {
		return nil, false
	}
	secretKey, _ := ageKeyPair()
	if secretKey == "" {
		return nil, false
	}
	plain, err := age.DecryptBytes(data, secretKey)
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
	_, stale, err := loadProfile(ctx, true)
	if err != nil {
		return false, err
	}
	if stale {
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
	go func() {
		defer close(done)
		runUpdater(ctx, interval, profileRetry.Load(), func() error {
			changed, err := refreshProfile(ctx)
			if err != nil || !changed || ctx.Err() != nil {
				// loadProfile already logged the fallback itself
				if err != nil && ctx.Err() == nil && !errors.Is(err, errProfileStale) {
					log.Warnln("[oixCloud] profile update failed: %s", err)
				}
				return err
			}
			profileUpdaterMu.Lock()
			reload := profileReloader
			profileUpdaterMu.Unlock()
			if reload != nil {
				log.Infoln("[oixCloud] profile changed, reloading")
				reload()
			}
			return nil
		})
	}()
}

// StopProfileUpdates waits for the updater, including a reload it is running.
// The updater stays registered until then, so that reload does not start
// another one.
func StopProfileUpdates() {
	profileUpdaterMu.Lock()
	cancel, done := profileCancel, profileDone
	profileUpdaterMu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
	profileUpdaterMu.Lock()
	if profileDone == done {
		profileCancel, profileDone = nil, nil
	}
	profileUpdaterMu.Unlock()
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
	if err := saveProfile(profilePath(), token, config.data); err != nil {
		return false, err
	}
	if err := persistToken(C.Path.HomeDir(), token); err != nil {
		log.Warnln("[oixCloud] persist token failed: %s", err)
	}
	SetToken(token)
	useProfile(config.plain)
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
