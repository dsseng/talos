// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package volumeconfig

import (
	"time"

	configconfig "github.com/siderolabs/talos/pkg/machinery/config/config"
	"github.com/siderolabs/talos/pkg/machinery/constants"
)

// ResolveScrub resolves the effective scrub configuration for a volume by combining the global
// FilesystemScrubConfig with the per-volume scrub override.
//
// Scrubbing is enabled by default with the default period; the global document adjusts or
// disables it for all volumes, and the per-volume override takes precedence over both.
//
// It returns enabled=false (and period=0) when scrubbing is disabled for the volume.
func ResolveScrub(cfg configconfig.Config, scrubConfig configconfig.VolumeScrubConfigProvider) (enabled bool, period time.Duration) {
	if cfg == nil {
		return false, 0
	}

	enabled = true
	period = constants.DefaultFilesystemScrubPeriod

	if globalScrub := cfg.FilesystemScrubConfig(); globalScrub != nil {
		enabled = globalScrub.Enabled().ValueOr(enabled)
		period = globalScrub.Period().ValueOr(period)
	}

	if scrubConfig != nil {
		if volumeScrub := scrubConfig.Scrub(); volumeScrub != nil {
			// a per-volume scrub block enables scrubbing unless explicitly disabled.
			enabled = volumeScrub.Enabled().ValueOr(true)

			if v, ok := volumeScrub.Period().Get(); ok {
				period = v
			}
		}
	}

	if !enabled || period <= 0 {
		return false, 0
	}

	return true, period
}
