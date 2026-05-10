// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package operator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/ndp"
	"go.uber.org/zap"

	"github.com/siderolabs/talos/pkg/machinery/resources/network"
)

// NDP watches NDP Router Advertisements on IPv6-capable links
// and configures networking stack (DHCPv6, DNS) accordingly
type NDP struct {
	logger *zap.Logger

	linkName string

	mu        sync.Mutex
	resolvers []network.ResolverSpecSpec
	///TODO: support Managed flag to enable DHCPv6
	///TODO: support Other flag, which should make hosts
	// only request DNS/NTP data from DHCPv6, and not ask for addresses
}

// NewNDP creates NDP operator.
func NewNDP(logger *zap.Logger, linkName string) *NDP {
	return &NDP{
		logger:   logger,
		linkName: linkName,
	}
}

// Prefix returns unique operator prefix which gets prepended to each spec.
func (d *NDP) Prefix() string {
	return fmt.Sprintf("ndp/%s", d.linkName)
}

// Run the operator loop.
//
//nolint:gocyclo
func (d *NDP) Run(ctx context.Context, notifyCh chan<- struct{}) {
	iface, err := net.InterfaceByName(d.linkName)
	if err != nil {
		d.logger.Warn("link not found", zap.String("link", d.linkName))
	}

	conn, _, err := ndp.Listen(iface, ndp.Unspecified)
	if err != nil {
		d.logger.Error("failed to listen for NDP", zap.Any("interface", iface))
		return
	}

	routerLifetimeTimer := time.NewTimer(0)
	// RDNSS DNS servers have a lifetime, and if not re-advertised
	// within that period they should no longer be used
	dnsLifetimeTimer := time.NewTimer(0)
	ch := make(chan *ndp.RouterAdvertisement)

	go (func() {
		for {
			msg, _, _, err := conn.ReadFrom()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					d.logger.Error("error receiving NDP messages", zap.Error(err))
				}

				break
			}

			ra, ok := msg.(*ndp.RouterAdvertisement)
			if !ok {
				continue
			}

			ch <- ra
		}
	})()

	for {
		select {
		case <-ctx.Done():
			err := conn.Close()
			if err != nil {
				d.logger.Error("failed to close NDP listener", zap.String("interface", d.linkName), zap.Error(err))
				continue
			}
			return
		case ra := <-ch:
			fmt.Println("managed", d.linkName, ra.ManagedConfiguration, ra.RouterLifetime)
			routerLifetimeTimer.Reset(ra.RouterLifetime)

			///FIXME: what if there are multiple routers, each of which advertises RDNSS?
			for _, o := range ra.Options {
				rdnss, ok := o.(*ndp.RecursiveDNSServer)
				if !ok {
					continue
				}

				dnsLifetimeTimer.Reset(rdnss.Lifetime)

				d.mu.Lock()
				d.resolvers = []network.ResolverSpecSpec{
					{
						DNSServers:  rdnss.Servers,
						ConfigLayer: network.ConfigOperator,
					},
				}
				d.mu.Unlock()
			}

			notifyCh <- struct{}{}
		case <-routerLifetimeTimer.C:
			fmt.Println("ra expired")
			d.mu.Lock()
			///TODO: Remove also Managed/Other and everything else derived from RA
			d.resolvers = []network.ResolverSpecSpec{}
			d.mu.Unlock()

			notifyCh <- struct{}{}
		case <-dnsLifetimeTimer.C:
			fmt.Println("rdnss expired")
			d.mu.Lock()
			d.resolvers = []network.ResolverSpecSpec{}
			d.mu.Unlock()

			notifyCh <- struct{}{}
		}
	}
}

// AddressSpecs implements Operator interface.
func (d *NDP) AddressSpecs() []network.AddressSpecSpec {
	return nil
}

// LinkSpecs implements Operator interface.
func (d *NDP) LinkSpecs() []network.LinkSpecSpec {
	return nil
}

// RouteSpecs implements Operator interface.
func (d *NDP) RouteSpecs() []network.RouteSpecSpec {
	return nil
}

// HostnameSpecs implements Operator interface.
func (d *NDP) HostnameSpecs() []network.HostnameSpecSpec {
	return nil
}

// ResolverSpecs implements Operator interface.
func (d *NDP) ResolverSpecs() []network.ResolverSpecSpec {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.resolvers
}

// TimeServerSpecs implements Operator interface.
func (d *NDP) TimeServerSpecs() []network.TimeServerSpecSpec {
	return nil
}
