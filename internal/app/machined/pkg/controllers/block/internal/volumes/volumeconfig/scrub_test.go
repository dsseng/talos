// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package volumeconfig_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/talos/internal/app/machined/pkg/controllers/block/internal/volumes/volumeconfig"
	configconfig "github.com/siderolabs/talos/pkg/machinery/config/config"
	"github.com/siderolabs/talos/pkg/machinery/config/container"
	blockcfg "github.com/siderolabs/talos/pkg/machinery/config/types/block"
	"github.com/siderolabs/talos/pkg/machinery/constants"
)

func TestResolveScrub(t *testing.T) {
	t.Parallel()

	const (
		globalPeriod = 24 * time.Hour
		customPeriod = 30 * time.Minute
	)

	globalDoc := func(mutate func(*blockcfg.FilesystemScrubConfigV1Alpha1)) *blockcfg.FilesystemScrubConfigV1Alpha1 {
		doc := blockcfg.NewFilesystemScrubConfigV1Alpha1()

		if mutate != nil {
			mutate(doc)
		}

		return doc
	}

	userVolume := func(name string, scrub *blockcfg.ScrubConfig) *blockcfg.UserVolumeConfigV1Alpha1 {
		doc := blockcfg.NewUserVolumeConfigV1Alpha1()
		doc.MetaName = name
		doc.ScrubSpec = scrub

		return doc
	}

	for _, tc := range []struct {
		name      string
		docs      []configconfig.Document
		volumeCfg configconfig.VolumeScrubConfigProvider

		expectedEnabled bool
		expectedPeriod  time.Duration
	}{
		{
			name:      "no config defaults to enabled",
			volumeCfg: nil,

			expectedEnabled: true,
			expectedPeriod:  constants.DefaultFilesystemScrubPeriod,
		},
		{
			name: "global period override",
			docs: []configconfig.Document{globalDoc(func(doc *blockcfg.FilesystemScrubConfigV1Alpha1) {
				doc.ScrubPeriod = globalPeriod
			})},
			volumeCfg: nil,

			expectedEnabled: true,
			expectedPeriod:  globalPeriod,
		},
		{
			name: "global disable",
			docs: []configconfig.Document{globalDoc(func(doc *blockcfg.FilesystemScrubConfigV1Alpha1) {
				doc.ScrubEnabled = new(false)
			})},
			volumeCfg: nil,
		},
		{
			name: "per-volume period override",
			docs: []configconfig.Document{globalDoc(func(doc *blockcfg.FilesystemScrubConfigV1Alpha1) {
				doc.ScrubPeriod = globalPeriod
			})},
			volumeCfg: userVolume("data", &blockcfg.ScrubConfig{ScrubPeriod: customPeriod}),

			expectedEnabled: true,
			expectedPeriod:  customPeriod,
		},
		{
			name:      "per-volume disable overrides default",
			volumeCfg: userVolume("data", &blockcfg.ScrubConfig{ScrubEnabled: new(false)}),
		},
		{
			name: "per-volume enable overrides global disable",
			docs: []configconfig.Document{globalDoc(func(doc *blockcfg.FilesystemScrubConfigV1Alpha1) {
				doc.ScrubEnabled = new(false)
				doc.ScrubPeriod = globalPeriod
			})},
			volumeCfg: userVolume("data", &blockcfg.ScrubConfig{}),

			expectedEnabled: true,
			expectedPeriod:  globalPeriod,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctr, err := container.New(tc.docs...)
			require.NoError(t, err)

			enabled, period := volumeconfig.ResolveScrub(ctr, tc.volumeCfg)

			assert.Equal(t, tc.expectedEnabled, enabled)
			assert.Equal(t, tc.expectedPeriod, period)
		})
	}
}
