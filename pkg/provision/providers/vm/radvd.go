// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package vm

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
	"golang.org/x/sync/errgroup"
)

const (
	// raInterval is how often unsolicited Router Advertisements are sent (and how often a failed sender is restarted).
	raInterval = 10 * time.Second
	// raRouterLifetime is the default router lifetime advertised for the bridge (the host acts as the IPv6 default gateway).
	raRouterLifetime = 30 * time.Minute
	// raPrefixValidLifetime and raPrefixPreferredLifetime are the lifetimes of the advertised on-link prefixes.
	raPrefixValidLifetime     = time.Hour
	raPrefixPreferredLifetime = 30 * time.Minute
	// raRDNSSLifetime is the lifetime of the advertised recursive DNS servers.
	raRDNSSLifetime = 30 * time.Minute
)

var (
	raAllNodes   = netip.MustParseAddr("ff02::1")
	raAllRouters = netip.MustParseAddr("ff02::2")
)

// RouterAdvertisementConfig describes IPv6 Router Advertisements sent on the cluster bridge.
type RouterAdvertisementConfig struct {
	// Prefixes are advertised as on-link prefixes.
	Prefixes []netip.Prefix
	// Managed sets the M (and O) flags, telling hosts to use DHCPv6 for addresses (and other configuration).
	Managed bool
	// Autonomous sets the A flag on the advertised prefixes, allowing hosts to use SLAAC.
	Autonomous bool
	// RDNSS is the list of recursive DNS servers to advertise (not advertised if empty).
	RDNSS []netip.Addr
}

// Message builds the Router Advertisement for the config, with the source link-layer address hwAddr.
func (cfg RouterAdvertisementConfig) Message(hwAddr net.HardwareAddr) *ndp.RouterAdvertisement {
	ra := &ndp.RouterAdvertisement{
		CurrentHopLimit:      64,
		ManagedConfiguration: cfg.Managed,
		OtherConfiguration:   cfg.Managed,
		RouterLifetime:       raRouterLifetime,
	}

	if len(hwAddr) > 0 {
		ra.Options = append(ra.Options, &ndp.LinkLayerAddress{
			Direction: ndp.Source,
			Addr:      hwAddr,
		})
	}

	for _, prefix := range cfg.Prefixes {
		ra.Options = append(ra.Options, &ndp.PrefixInformation{
			PrefixLength:                   uint8(prefix.Bits()),
			OnLink:                         true,
			AutonomousAddressConfiguration: cfg.Autonomous,
			ValidLifetime:                  raPrefixValidLifetime,
			PreferredLifetime:              raPrefixPreferredLifetime,
			Prefix:                         prefix.Masked().Addr(),
		})
	}

	if len(cfg.RDNSS) > 0 {
		ra.Options = append(ra.Options, &ndp.RecursiveDNSServer{
			Lifetime: raRDNSSLifetime,
			Servers:  cfg.RDNSS,
		})
	}

	return ra
}

// RADVD sends IPv6 Router Advertisements on the interface until the context is canceled.
//
// Advertisements are sent periodically and in response to Router Solicitations.
// The sender is restarted on failure, so it tolerates the interface (or its link-local address) not being ready yet.
func RADVD(ctx context.Context, ifName string, cfg RouterAdvertisementConfig) error {
	for {
		err := serveRA(ctx, ifName, cfg)
		if ctx.Err() != nil {
			return nil //nolint:nilerr
		}

		log.Printf("RA: sender on %s failed, retrying in %s: %s", ifName, raInterval, err)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(raInterval):
		}
	}
}

//nolint:gocyclo
func serveRA(ctx context.Context, ifName string, cfg RouterAdvertisementConfig) error {
	ifi, err := net.InterfaceByName(ifName)
	if err != nil {
		return fmt.Errorf("error looking up interface: %w", err)
	}

	conn, llAddr, err := ndp.Listen(ifi, ndp.LinkLocal)
	if err != nil {
		return fmt.Errorf("error listening on link-local address: %w", err)
	}

	defer conn.Close() //nolint:errcheck

	// only Router Solicitations are of interest
	var filter ipv6.ICMPFilter

	filter.SetAll(true)
	filter.Accept(ipv6.ICMPTypeRouterSolicitation)

	if err = conn.SetICMPFilter(&filter); err != nil {
		return fmt.Errorf("error setting ICMPv6 filter: %w", err)
	}

	if err = conn.JoinGroup(raAllRouters); err != nil {
		return fmt.Errorf("error joining all-routers multicast group: %w", err)
	}

	ra := cfg.Message(ifi.HardwareAddr)

	log.Printf("RA: sending router advertisements on %s from %s (managed: %v, autonomous: %v, prefixes: %v, rdnss: %v)",
		ifName, llAddr, cfg.Managed, cfg.Autonomous, cfg.Prefixes, cfg.RDNSS)

	eg, egCtx := errgroup.WithContext(ctx)

	// unblock the reader on shutdown/failure
	stop := context.AfterFunc(egCtx, func() {
		conn.Close() //nolint:errcheck
	})
	defer stop()

	eg.Go(func() error {
		for {
			msg, _, from, err := conn.ReadFrom()
			if err != nil {
				if egCtx.Err() != nil {
					return nil //nolint:nilerr
				}

				return fmt.Errorf("error reading: %w", err)
			}

			if _, ok := msg.(*ndp.RouterSolicitation); !ok {
				continue
			}

			log.Printf("RA: got router solicitation from %s", from)

			if err = conn.WriteTo(ra, nil, raAllNodes); err != nil {
				return fmt.Errorf("error sending solicited router advertisement: %w", err)
			}
		}
	})

	eg.Go(func() error {
		ticker := time.NewTicker(raInterval)
		defer ticker.Stop()

		for {
			if err := conn.WriteTo(ra, nil, raAllNodes); err != nil {
				return fmt.Errorf("error sending router advertisement: %w", err)
			}

			select {
			case <-egCtx.Done():
				return nil
			case <-ticker.C:
			}
		}
	})

	return eg.Wait()
}
