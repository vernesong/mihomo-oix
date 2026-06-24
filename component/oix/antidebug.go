package oix

import (
	"os"

	"github.com/metacubex/mihomo/log"
)

// GuardStartup refuses to start when a debugger is attached, protecting the
// decrypted oix node material from being dumped.
func GuardStartup() {
	if debuggerPresent() {
		log.Warnln("oix: debugger detected, refusing to start")
		os.Exit(1)
	}
	if injectionDetected() {
		log.Warnln("oix: library injection detected, refusing to start")
		os.Exit(1)
	}
}

func injectionDetected() bool {
	for _, key := range []string{"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "LD_AUDIT"} {
		if os.Getenv(key) != "" {
			return true
		}
	}
	return false
}
