// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package selinux provides generic code for managing SELinux.
package selinux

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"

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

		return SetLabel(path, label)
	})
}

// RelabelDirectoryRecursive ensures files SELinux labels match expected ones under specified root.
// TODO: skip relabeling a root by a flag file:
// We set this file when relabeling, and normally we never need to relabel while running with SE enabled
// However if the system has been running without SELinux, new files didn't get labels, so on such boot flags must be removed
func RelabelDirectoryRecursive(root string) error {
	if root == constants.SystemPath {
		debug.PrintStack()
	}
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

// RelabelDirectory ensures directory SELinux label matches expected one.
func RelabelDirectory(root string) error {
	if root == constants.SystemPath {
		debug.PrintStack()
	}
	for _, l := range labels {
		if !strings.HasPrefix(root, l.Prefix) {
			continue
		}

		fmt.Println("selinux: Relabeling single", l.Prefix, "to", l.Label)
		if err := SetLabel(l.Prefix, l.Label); err != nil {
			return err
		}
	}

	return nil
}

// goroutine 1 [running]:
// runtime/debug.Stack()
//         /toolchain/go/src/runtime/debug/stack.go:26 +0x5e
// runtime/debug.PrintStack()
//         /toolchain/go/src/runtime/debug/[    0.599721] ima: policy update completed
// stack.go:18 +0x13
// github.com/siderolabs/talos/internal/pkg/selinux.RelabelDirectory({0x37be4f9, 0x7})
//         /src/internal/pkg/selinux/relabeling.go:107 +0x4d
// github.com/siderolabs/talos/internal/pkg/mount/v2.(*Point).mount(0xc000845c80)
//         /src/internal/pkg/mount/v2/mount.go:308 +0x75
// github.com/siderolabs/talos/internal/pkg/mount/v2.(*Point).retry.func1()
//         /src/internal/pkg/mount/v2/mount.go:325 +0x38
// github.com/siderolabs/go-retry/retry.constantRetryer.Retry.removeContext.func1({0x0?, 0x0?})
//         /.cache/mod/github.com/siderolabs/go-retry@v0.3.3/retry/retry.go:27 +0x13
// github.com/siderolabs/go-retry/retry.retry.func2(0x3d8dcb8?, 0x5fa65a0?, 0x12a05f200?)
//         /.cache/mod/github.com/siderolabs/go-retry@v0.3.3/retry/retry.go:233 +0x83
// github.com/siderolabs/go-retry/retry.retry({0x3d8dd98, 0xc000172a80}, 0xc00068fa60, 0xc00068f9e8?, {0x3d77b10, 0xc0008328a0}, 0xc00083b640)
//         /.cache/mod/github.com/siderolabs/go-retry@v0.3.3/retry/retry.go:234 +0x108
// github.com/siderolabs/go-retry/retry.constantRetryer.RetryWithContext({{0xc00083b640?, 0x3324460?}}, {0x3d8dcb8, 0x5fa65a0}, 0xc00068fa60)
//         /.cache/mod/github.com/siderolabs/go-retry@v0.3.3/retry/constant.go:56 +0x10b
// github.com/siderolabs/go-retry/retry.constantRetryer.Retry({{0xc00083b640?, 0x34a9820?}}, 0x12a05f201?)
//         /.cache/mod/github.com/siderolabs/go-retry@v0.3.3/retry/constant.go:48 +0x3c
// github.com/siderolabs/talos/internal/pkg/mount/v2.(*Point).retry(0xc000845c80, 0xc000856810, 0x0, {0xc000832858?})
//         /src/internal/pkg/mount/v2/mount.go:324 +0xe6
// github.com/siderolabs/talos/internal/pkg/mount/v2.(*Point).Mount(0xc000845c80, {0x0, 0x0, 0xfcfc60?})
//         /src/internal/pkg/mount/v2/mount.go:258 +0x43f
// github.com/siderolabs/talos/internal/pkg/mount/v2.Points.Mount({0xc000832840, 0x3, 0x0?}, {0x0, 0x0, 0x0})
//         /src/internal/pkg/mount/v2/points.go:21 +0xc5
// github.com/siderolabs/talos/internal/app/machined/pkg/startup.MountPseudoLate({0x3d8dd28, 0xc00059bb80}, 0xc000845a80, {0x3dbc0f8, 0xc00059bb30}, 0xc00084d620)
//         /src/internal/app/machined/pkg/startup/tasks.go:94 +0x8a
// github.com/siderolabs/talos/internal/app/machined/pkg/startup.LogMode({0x3d8dd28, 0xc00059bb80}, 0xc000845a80, {0x3dbc0f8, 0xc00059bb30}, 0xc00084d620)
//         /src/internal/app/machined/pkg/startup/tasks.go:29 +0x172
// github.com/siderolabs/talos/internal/app/machined/pkg/startup.RunTasks({0x3d8dd28, 0xc00059bb80}, 0xc000845a80, {0x3dbc0f8, 0xc00059bb30}, {0xc000247b80, 0xb, 0x14})
//         /src/internal/app/machined/pkg/startup/startup.go:34 +0xd6
// main.run()
//         /src/internal/app/machined/main.go:189 +0x2a5
// main.main()
//         /src/internal/app/machined/main.go:349 +0x1bb
