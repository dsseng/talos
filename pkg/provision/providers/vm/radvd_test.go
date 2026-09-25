// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package vm_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/mdlayher/ndp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/talos/pkg/provision/providers/vm"
)

func TestRouterAdvertisementMessage(t *testing.T) {
	t.Parallel()

	hwAddr := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	for _, test := range []struct {
		name string
		cfg  vm.RouterAdvertisementConfig
	}{
		{
			name: "managed",
			cfg: vm.RouterAdvertisementConfig{
				Prefixes: []netip.Prefix{netip.MustParsePrefix("fd74:616c:a05::/64")},
				Managed:  true,
			},
		},
		{
			name: "autonomous with rdnss",
			cfg: vm.RouterAdvertisementConfig{
				Prefixes:   []netip.Prefix{netip.MustParsePrefix("fd74:616c:a05::1/64")},
				Autonomous: true,
				RDNSS:      []netip.Addr{netip.MustParseAddr("fd74:616c:a05::1")},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			b, err := ndp.MarshalMessage(test.cfg.Message(hwAddr))
			require.NoError(t, err)

			msg, err := ndp.ParseMessage(b)
			require.NoError(t, err)

			ra, ok := msg.(*ndp.RouterAdvertisement)
			require.True(t, ok)

			assert.Equal(t, test.cfg.Managed, ra.ManagedConfiguration)
			assert.Equal(t, test.cfg.Managed, ra.OtherConfiguration)
			assert.NotZero(t, ra.RouterLifetime)

			var (
				prefixes []netip.Prefix
				rdnss    []netip.Addr
				llAddr   net.HardwareAddr
			)

			for _, opt := range ra.Options {
				switch opt := opt.(type) {
				case *ndp.LinkLayerAddress:
					assert.Equal(t, ndp.Source, opt.Direction)

					llAddr = opt.Addr
				case *ndp.PrefixInformation:
					assert.True(t, opt.OnLink)
					assert.Equal(t, test.cfg.Autonomous, opt.AutonomousAddressConfiguration)

					prefixes = append(prefixes, netip.PrefixFrom(opt.Prefix, int(opt.PrefixLength)))
				case *ndp.RecursiveDNSServer:
					rdnss = append(rdnss, opt.Servers...)
				}
			}

			expectedPrefixes := make([]netip.Prefix, 0, len(test.cfg.Prefixes))
			for _, prefix := range test.cfg.Prefixes {
				expectedPrefixes = append(expectedPrefixes, prefix.Masked())
			}

			assert.Equal(t, hwAddr, llAddr)
			assert.Equal(t, expectedPrefixes, prefixes)
			assert.Equal(t, test.cfg.RDNSS, rdnss)
		})
	}
}
