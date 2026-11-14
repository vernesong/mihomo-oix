// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (!linux || android) && !freebsd && !openbsd && !windows && !darwin && !illumos && !solaris && !plan9

package dns

import (
	"github.com/metacubex/tailscale/control/controlknobs"
	"github.com/metacubex/tailscale/health"
	"github.com/metacubex/tailscale/types/logger"
	"github.com/metacubex/tailscale/util/eventbus"
	"github.com/metacubex/tailscale/util/syspolicy/policyclient"
)

// NewOSConfigurator creates a new OS configurator.
//
// The health tracker and the knobs may be nil and are ignored on this platform.
func NewOSConfigurator(logger.Logf, *health.Tracker, *eventbus.Bus, policyclient.Client, *controlknobs.Knobs, string) (OSConfigurator, error) {
	return NewNoopManager()
}
