// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package talos

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/siderolabs/talos/cmd/talosctl/pkg/talos/helpers"
	"github.com/siderolabs/talos/pkg/machinery/api/common"
	"github.com/siderolabs/talos/pkg/machinery/client"
)

var pingArgs struct {
	iface    string
	ttl      uint32
	interval time.Duration
}

var pingCmd = &cobra.Command{
	Use:   "ping <host>",
	Short: "Ping a network host",
	Long:  ``,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return WithClient(func(ctx context.Context, c *client.Client) error {
			fmt.Printf("Pinging %s\n", args[0])
			stream, err := c.Ping(ctx, args[0], pingArgs.iface, pingArgs.ttl, pingArgs.interval)
			if err != nil {
				return fmt.Errorf("error fetching logs: %s", err)
			}
			fmt.Printf("Pinging %s\n", args[0])

			// for {
			// 	fmt.Printf("reading %s\n", args[0])
			// 	data, err := stream.Recv()
			// 	fmt.Println(data, err)
			// 	if data.Metadata != nil && data.Metadata.Error != "" {
			// 		_, err = fmt.Fprintf(os.Stderr, "ERROR: %s\n", data.Metadata.Error)
			// 		if err != nil {
			// 			return err
			// 		}

			// 		continue
			// 	}

			// 	_, err = fmt.Println(data.Bytes)
			// 	if err != nil {
			// 		return err
			// 	}
			// }
			return helpers.ReadGRPCStream(stream, func(data *common.Data, node string, multipleNodes bool) error {
				fmt.Println("data", data.Bytes)

				return nil
			})
		})
	},
}

func init() {
	pingCmd.Flags().StringVarP(&pingArgs.iface, "interface", "I", "", "interface to use")
	pingCmd.Flags().Uint32VarP(&pingArgs.ttl, "ttl", "t", 64, "time to live")
	pingCmd.Flags().DurationVarP(&pingArgs.interval, "interval", "i", 500*time.Millisecond, "interval between pings")

	addCommand(pingCmd)
}
