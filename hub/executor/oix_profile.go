package executor

import (
	"sync"

	"github.com/metacubex/mihomo/component/oix"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

var reloadMu sync.Mutex

// ReloadConfig re-reads and applies the config file. Account changes and
// profile updates go through it one at a time, so an older managed profile
// never replaces a newer one.
func ReloadConfig() error {
	reloadMu.Lock()
	defer reloadMu.Unlock()
	cfg, err := ParseWithPath(C.Path.Config())
	if err != nil {
		return err
	}
	ApplyConfig(cfg, false)
	return nil
}

func init() {
	oix.SetProfileReloader(func() {
		if err := ReloadConfig(); err != nil {
			log.Warnln("[oixCloud] reload profile: %s", err)
		}
	})
}
