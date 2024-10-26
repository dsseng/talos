// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package selinux provides generic code for managing SELinux.
package selinux

import (
	"github.com/siderolabs/go-procfs/procfs"
	"golang.org/x/sys/unix"

	"github.com/siderolabs/talos/pkg/machinery/constants"
)

// SELinuxEnabled checks if SELinux is enabled on the system by reading
// the kernel command line. It returns true if SELinux is enabled,
// otherwise it returns false.
// TODO: check for running in a container as well.
func SELinuxEnabled() bool {
	val := procfs.ProcCmdline().Get(constants.KernelParamSELinux).First()
	return val != nil
}

// SetLabel sets label for file or directory, following symlinks
// It does not perform the operation in case SELinux is disabled or provided label is empty
func SetLabel(filename string, label string) error {
	if label == "" {
		return nil
	}

	if SELinuxEnabled() {
		if err := unix.Lsetxattr(filename, "security.selinux", []byte(label), 0); err != nil {
			return err
		}
	}

	return nil
}
