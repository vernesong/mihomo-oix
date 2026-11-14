// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"github.com/metacubex/tailscale/control/controlknobs"
	"github.com/metacubex/tailscale/health"
	"github.com/metacubex/tailscale/types/logger"
	"github.com/metacubex/tailscale/util/eventbus"
	"github.com/metacubex/tailscale/util/syspolicy/policyclient"
)

func NewOSConfigurator(logf logger.Logf, health *health.Tracker, bus *eventbus.Bus, _ policyclient.Client, _ *controlknobs.Knobs, iface string) (OSConfigurator, error) {
	return newDirectManager(logf, health, bus), nil
}
