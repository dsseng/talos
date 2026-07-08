// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package block

//docgen:jsonschema

import (
	"fmt"
	"time"

	"github.com/siderolabs/gen/optional"
)

// ScrubConfig describes per-volume filesystem scrub configuration.
//
// It overrides the global FilesystemScrubConfig for the volume.
type ScrubConfig struct {
	//   description: |
	//     Enable or disable scrubbing for this volume.
	//
	//     If not set, scrubbing is enabled by default.
	ScrubEnabled *bool `yaml:"enabled,omitempty"`
	//   description: |
	//     The period at which the volume is scrubbed, overriding the global scrub period.
	//   schema:
	//     type: string
	//     pattern: ^[-+]?(((\d+(\.\d*)?|\d*(\.\d+)+)([nuµm]?s|m|h))|0)+$
	ScrubPeriod time.Duration `yaml:"period,omitempty"`
}

// Validate the scrub configuration.
func (s *ScrubConfig) Validate() error {
	if s == nil {
		return nil
	}

	if s.ScrubPeriod != 0 && s.ScrubPeriod < MinScrubPeriod {
		return fmt.Errorf("scrub period: minimum value is %s", MinScrubPeriod)
	}

	return nil
}

// Enabled implements config.VolumeScrubConfig interface.
func (s *ScrubConfig) Enabled() optional.Optional[bool] {
	if s == nil || s.ScrubEnabled == nil {
		return optional.None[bool]()
	}

	return optional.Some(*s.ScrubEnabled)
}

// Period implements config.VolumeScrubConfig interface.
func (s *ScrubConfig) Period() optional.Optional[time.Duration] {
	if s == nil || s.ScrubPeriod == 0 {
		return optional.None[time.Duration]()
	}

	return optional.Some(s.ScrubPeriod)
}
