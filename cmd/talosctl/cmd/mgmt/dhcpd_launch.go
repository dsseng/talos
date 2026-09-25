// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux || darwin

package mgmt

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/siderolabs/gen/xslices"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/siderolabs/talos/pkg/provision/providers/vm"
)

var dhcpdLaunchCmdFlags struct {
	addr            string
	ifName          string
	statePath       string
	ipxeNextHandler string

	raPrefixes   []string
	raManaged    bool
	raAutonomous bool
	raRDNSS      []string
}

// dhcpdLaunchCmd represents the dhcpd-launch command.
var dhcpdLaunchCmd = &cobra.Command{
	Use:    "dhcpd-launch",
	Short:  "Internal command used by VM provisioners",
	Long:   ``,
	Args:   cobra.NoArgs,
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		ips := xslices.Map(slices.Collect(strings.SplitSeq(dhcpdLaunchCmdFlags.addr, ",")), net.ParseIP)

		eg, ctx := errgroup.WithContext(cmd.Context())

		eg.Go(func() error {
			return vm.DHCPd(ctx, dhcpdLaunchCmdFlags.ifName, ips, dhcpdLaunchCmdFlags.statePath)
		})

		if len(dhcpdLaunchCmdFlags.raPrefixes) > 0 {
			raCfg, err := dhcpdLaunchRAConfig()
			if err != nil {
				return err
			}

			eg.Go(func() error {
				return vm.RADVD(ctx, dhcpdLaunchCmdFlags.ifName, raCfg)
			})
		}

		if dhcpdLaunchCmdFlags.ipxeNextHandler != "" {
			eg.Go(func() error {
				return vm.TFTPd(ctx, ips, dhcpdLaunchCmdFlags.ipxeNextHandler)
			})
		}

		return eg.Wait()
	},
}

func dhcpdLaunchRAConfig() (vm.RouterAdvertisementConfig, error) {
	cfg := vm.RouterAdvertisementConfig{
		Managed:    dhcpdLaunchCmdFlags.raManaged,
		Autonomous: dhcpdLaunchCmdFlags.raAutonomous,
	}

	for _, s := range dhcpdLaunchCmdFlags.raPrefixes {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return cfg, fmt.Errorf("error parsing RA prefix %q: %w", s, err)
		}

		cfg.Prefixes = append(cfg.Prefixes, prefix)
	}

	for _, s := range dhcpdLaunchCmdFlags.raRDNSS {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return cfg, fmt.Errorf("error parsing RA RDNSS address %q: %w", s, err)
		}

		cfg.RDNSS = append(cfg.RDNSS, addr)
	}

	return cfg, nil
}

func init() {
	dhcpdLaunchCmd.Flags().StringVar(&dhcpdLaunchCmdFlags.addr, "addr", "localhost", "IP addresses to listen on")
	dhcpdLaunchCmd.Flags().StringVar(&dhcpdLaunchCmdFlags.ifName, "interface", "", "interface to listen on")
	dhcpdLaunchCmd.Flags().StringVar(&dhcpdLaunchCmdFlags.statePath, "state-path", "", "path to state directory")
	dhcpdLaunchCmd.Flags().StringVar(&dhcpdLaunchCmdFlags.ipxeNextHandler, "ipxe-next-handler", "", "iPXE script to chain load")
	dhcpdLaunchCmd.Flags().StringSliceVar(&dhcpdLaunchCmdFlags.raPrefixes, "ipv6-ra-prefixes", nil, "IPv6 prefixes to advertise via Router Advertisements (RA disabled if empty)")
	dhcpdLaunchCmd.Flags().BoolVar(&dhcpdLaunchCmdFlags.raManaged, "ipv6-ra-managed", false, "set the managed (M) and other configuration (O) flags in Router Advertisements")
	dhcpdLaunchCmd.Flags().BoolVar(&dhcpdLaunchCmdFlags.raAutonomous, "ipv6-ra-autonomous", false, "set the autonomous (A) flag on prefixes in Router Advertisements")
	dhcpdLaunchCmd.Flags().StringSliceVar(&dhcpdLaunchCmdFlags.raRDNSS, "ipv6-ra-rdnss", nil, "recursive DNS servers to advertise via Router Advertisements")
	addCommand(dhcpdLaunchCmd)
}
