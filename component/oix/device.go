package oix

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// The panel counts an account's devices by this random per-install identifier.
// It is not a credential, is never derived from hardware, and must not travel
// with a backup to another device.
const oixDeviceHeader = "X-oixCloud-Device"

var deviceIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

var (
	deviceMu       sync.Mutex
	declaredDevice string
	// the identifier kept in a home directory, or a home directory where keeping one failed
	storedHome   string
	storedDevice string
)

func normalizeDeviceID(id string) (string, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	return id, deviceIDPattern.MatchString(id)
}

// SetDevice declares an identifier the front end keeps itself, for platforms
// whose home directory does not survive a reboot, such as the Asus Merlin
// plugin that runs the core from /tmp.
func SetDevice(id string) error {
	normalized, ok := normalizeDeviceID(id)
	if !ok {
		return fmt.Errorf("invalid oixCloud device ID %q", id)
	}
	deviceMu.Lock()
	declaredDevice = normalized
	deviceMu.Unlock()
	return nil
}

func deviceFilePath(homeDir string) string {
	return filepath.Join(homeDir, ".oix_device_id")
}

// currentDevice returns the declared identifier, then OIX_DEVICE for the CLI,
// which does not parse the core's flags, then one kept in the home directory
// and generated on first use. Without a place to keep it nothing is sent:
// a new identifier on every run would count as another device.
func currentDevice() string {
	deviceMu.Lock()
	defer deviceMu.Unlock()
	if declaredDevice != "" {
		return declaredDevice
	}
	if id, ok := normalizeDeviceID(os.Getenv("OIX_DEVICE")); ok {
		return id
	}
	homeDir := C.Path.HomeDir()
	if homeDir == "" {
		return ""
	}
	if storedHome == homeDir {
		return storedDevice
	}
	storedHome, storedDevice = homeDir, ""
	path := deviceFilePath(homeDir)
	if data, err := readPrivateFile(path); err == nil {
		if id, ok := normalizeDeviceID(string(data)); ok {
			storedDevice = id
			return id
		}
	}
	id, err := newDeviceID()
	if err == nil {
		err = writePrivateFile(path, []byte(id))
	}
	if err != nil {
		log.Warnln("[oixCloud] persist device ID failed: %s", err)
		return ""
	}
	storedDevice = id
	return id
}

func newDeviceID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func setDeviceHeader(req *http.Request) {
	if id := currentDevice(); id != "" {
		req.Header.Set(oixDeviceHeader, id)
	}
}
