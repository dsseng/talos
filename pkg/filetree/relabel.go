// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package filetree

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/siderolabs/talos/internal/pkg/selinux"
	"github.com/siderolabs/talos/pkg/machinery/constants"
)

type Label struct {
	Prefix string
	Label  string
}

// FS prefixes and matching SELinux libraries
// This list includes filesystems and directories on them
// It is ordered as subdirectories go before their parents as they must be excluded from parent relabeling
// TODO: label /var/lib/kubelet as kubelet private data
// TODO: maybe use a trie here for better perf?
// TODO: encode this using filecon statement in the policy? Will have to exclude ones that belong to squashfs though
var labels = []Label{
	{constants.SystemEtcPath, constants.SystemEtcSelinuxLabel},
	{constants.SystemVarPath, constants.SystemVarSelinuxLabel},
	{constants.StateMountPoint, constants.StateSelinuxLabel},
	{constants.SystemPath, constants.SystemSelinuxLabel}, // typically mounted & relabeled while empty
	{constants.RunPath, constants.RunSelinuxLabel},       // typically mounted & relabeled while empty
	{constants.EtcdDataPath, constants.EtcdDataSELinuxLabel},
	{constants.EphemeralMountPoint, constants.EphemeralSelinuxLabel},
}

func getDevID(path string) uint64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}

	return uint64(stat.Dev)
}

// SetLabelRecursive changes file SELinux labels recursively from the specified directory.
// It does not touch subdirectories with other labels by excluding prefixes from a list.
func SetLabelRecursive(root, label string, excl []Label) error {
	rootID := getDevID(root)
	return filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if getDevID(path) != rootID {
			fmt.Println("selinux: skipping cross-device", path)
			return filepath.SkipDir
		}

		// If we find an exclusion (e.g. a subdirectory that must have different label) skip that subtree
		for _, l := range excl {
			if strings.HasPrefix(path, l.Prefix) {
				fmt.Println("selinux: Relabeling to", label, ": SkipDir for", path, "it should be", l.Label)
				return fs.SkipDir
			}
		}

		return selinux.SetLabel(path, label)
	})
}

// RelabelRecursive ensures files SELinux labels match expected ones under specified root.
// TODO: skip relabeling a root by a flag file:
// We set this file when relabeling, and normally we never need to relabel while running with SE enabled
// However if the system has been running without SELinux, new files didn't get labels, so on such boot flags must be removed
func RelabelRecursive(root string) error {
	for i, l := range labels {
		// Set labels for everything under the given root
		if !strings.HasPrefix(root, l.Prefix) {
			continue
		}

		fmt.Println("selinux: Relabeling", l.Prefix, "to", l.Label)
		if err := SetLabelRecursive(l.Prefix, l.Label, labels[:i]); err != nil {
			return err
		}
	}

	return nil
}

// Relabel ensures files SELinux label matches expected one for the directory or mount.
func Relabel(root string) error {
	for _, l := range labels {
		if !strings.HasPrefix(root, l.Prefix) {
			continue
		}

		fmt.Println("selinux: Relabeling single", l.Prefix, "to", l.Label)
		if err := selinux.SetLabel(l.Prefix, l.Label); err != nil {
			return err
		}
	}

	return nil
}
