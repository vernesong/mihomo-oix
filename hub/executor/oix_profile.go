package executor

import (
	"github.com/metacubex/mihomo/component/oix"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// A changed managed profile is applied the way a controller reload applies a
// changed config file.
func init() {
	oix.SetProfileReloader(func() {
		cfg, err := ParseWithPath(C.Path.Config())
		if err != nil {
			log.Warnln("[oixCloud] reload profile: %s", err)
			return
		}
		ApplyConfig(cfg, false)
	})
}
