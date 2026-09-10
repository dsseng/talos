// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package selinux provides generic code for managing SELinux.
package selinux

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"

	"github.com/pkg/xattr"
	"github.com/siderolabs/go-procfs/procfs"
	"golang.org/x/sys/unix"

	"github.com/siderolabs/talos/internal/pkg/containermode"
	"github.com/siderolabs/talos/pkg/machinery/constants"
	"github.com/siderolabs/talos/pkg/xfs"
)

//go:embed policy/policy.33
var policy []byte

// IsEnabled checks if SELinux is enabled on the system by reading
// the kernel command line. It returns true if SELinux is enabled,
// otherwise it returns false. It also ensures we're not in a container.
// By default SELinux is disabled.
var IsEnabled = sync.OnceValue(func() bool {
	if containermode.InContainer() {
		return false
	}

	val := procfs.ProcCmdline().Get(constants.KernelParamSELinux).First()

	var selinuxFSPresent bool

	if _, err := os.Stat("/sys/fs/selinux"); err == nil {
		selinuxFSPresent = true
	}

	return val != nil && *val == "1" && selinuxFSPresent
})

// IsEnforcing checks if SELinux is enabled and the mode should be enforcing.
// By default if SELinux is enabled we consider it to be permissive.
var IsEnforcing = sync.OnceValue(func() bool {
	if !IsEnabled() {
		return false
	}

	val := procfs.ProcCmdline().Get(constants.KernelParamSELinuxEnforcing).First()

	return val != nil && *val == "1"
})

// GetLabel gets label for file, directory or symlink (not following symlinks)
// It does not perform the operation in case SELinux is disabled.
//
// A path that carries no security.selinux xattr at all - e.g. a file that was created on a
// system where SELinux was never enabled, or under an older Talos version that predates SELinux
// support - is not an error: it is reported as an empty label, exactly like FGetLabel does.
func GetLabel(filename string) (string, error) {
	if !IsEnabled() {
		return "", nil
	}

	label, err := xattr.LGet(filename, "security.selinux")
	if err != nil {
		if errors.Is(err, xattr.ENOATTR) {
			return "", nil
		}

		return "", err
	}

	if label == nil {
		return "", nil
	}

	return string(bytes.Trim(label, "\x00\n")), nil
}

// SetLabel sets label for file, directory or symlink (not following symlinks)
// It does not perform the operation in case SELinux is disabled, provided label is empty or already set.
func SetLabel(filename string, label string, excludeLabels ...string) error {
	if label == "" || !IsEnabled() {
		return nil
	}

	currentLabel, err := GetLabel(filename)
	if err != nil {
		return err
	}

	// Skip extra FS transactions when labels are okay.
	if currentLabel == label {
		return nil
	}

	// Skip setting label if it's in excludeLabels.
	if currentLabel != "" && slices.Contains(excludeLabels, currentLabel) {
		return nil
	}

	// We use LGet/LSet so that we manipulate label on the exact path, not the symlink target.
	if err := xattr.LSet(filename, "security.selinux", []byte(label)); err != nil {
		return err
	}

	return nil
}

// FGetLabel gets label for file, directory or symlink (not following symlinks) using provided root.
// It does not perform the operation in case SELinux is disabled.
func FGetLabel(root xfs.Root, filename string) (string, error) {
	if !IsEnabled() {
		return "", nil
	}

	f, err := xfs.OpenFile(root, filename, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck

	osf, err := xfs.AsOSFile(f, filename)
	if err != nil {
		return "", err
	}
	defer osf.Close() //nolint:errcheck

	label, err := xattr.FGet(osf, "security.selinux")
	if err != nil {
		if errors.Is(err, xattr.ENOATTR) {
			return "", nil
		}

		return "", err
	}

	if label == nil {
		return "", nil
	}

	return string(bytes.Trim(label, "\x00\n")), nil
}

// FSetLabel sets label for file, directory or symlink (not following symlinks) using provided root.
// It does not perform the operation in case SELinux is disabled, provided label is empty or already set.
func FSetLabel(root xfs.Root, filename string, label string, excludeLabels ...string) error {
	if label == "" || !IsEnabled() {
		return nil
	}

	currentLabel, err := FGetLabel(root, filename)
	if err != nil {
		return err
	}

	// Skip extra FS transactions when labels are okay.
	if currentLabel == label {
		return nil
	}

	// Skip setting label if it's in excludeLabels.
	if currentLabel != "" && slices.Contains(excludeLabels, currentLabel) {
		return nil
	}

	f, err := xfs.Open(root, filename)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck

	osf, err := xfs.AsOSFile(f, filename)
	if err != nil {
		return err
	}
	defer osf.Close() //nolint:errcheck

	// We use FGet/FSet so that we manipulate label on the exact path, not the symlink target.
	if err := xattr.FSet(osf, "security.selinux", []byte(label)); err != nil {
		return err
	}

	return nil
}

// RelabelStats summarizes a recursive relabel pass performed by SetLabelRecursive.
type RelabelStats struct {
	// Scanned is the number of filesystem entries whose label was inspected.
	Scanned int
	// Relabeled is the number of entries whose label actually had to be changed.
	Relabeled int
}

// NeedsRelabel performs a cheap, non-recursive spot-check for whether dir's content is
// consistent with label: it compares dir itself and its immediate children (one level deep)
// against the expected label, without descending any further.
//
// This is meant to be run unconditionally on every boot (once a volume is mounted) as a trigger
// for a full SetLabelRecursive pass: it is cheap enough to always run, and a mismatch found here
// is good evidence that the volume was written to under a different (or no) SELinux labeling
// regime - e.g. after an upgrade from a version that predates SELinux support, or after SELinux
// was enabled in the machine config (which, since the mode is fixed at UKI/cmdline build time,
// always implies a reboot, giving this check a chance to run).
//
// skipPaths are absolute paths (typically direct children of dir) to exclude from the check -
// these are the mount targets of nested volumes that legitimately carry their own, different
// label (e.g. /var/lib/kubelet/seccomp under /var/lib/kubelet): they are outside the scope of
// this relabel pass entirely, and are checked (and repaired) by their own volume's mount handling.
//
// It intentionally does not catch corruption below the sampled depth (e.g. a single mislabeled
// file deep inside a large CRI or kubelet tree): that is the accepted cost of not walking the
// whole tree on every boot.
func NeedsRelabel(dir string, label string, skipPaths ...string) (bool, error) {
	if label == "" || !IsEnabled() {
		return false, nil
	}

	skip := make(map[string]struct{}, len(skipPaths))
	for _, p := range skipPaths {
		skip[filepath.Clean(p)] = struct{}{}
	}

	paths := []string{dir}

	children, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("failed to read directory %q: %w", dir, err)
	}

	for _, child := range children {
		childPath := filepath.Join(dir, child.Name())

		if _, ok := skip[childPath]; ok {
			continue
		}

		paths = append(paths, childPath)
	}

	for _, path := range paths {
		current, err := GetLabel(path)
		if err != nil {
			// can't tell, be conservative and let the full pass sort it out
			return true, nil //nolint:nilerr
		}

		if current != label {
			return true, nil
		}
	}

	return false, nil
}

// SetLabelRecursive sets label for directory and its content recursively.
// It does not perform the operation in case SELinux is disabled, provided label is empty or already set.
//
// The walk does not descend into skipPaths (absolute paths, typically mount targets of nested
// volumes carrying their own, different label - see NeedsRelabel) nor into a different mounted
// filesystem found under dir: either case is relabeled independently, by its own volume's mount
// handling, and must never be overwritten with dir's label - doing so would silently undo a more
// specific label with a broader one.
//
// Only entries whose current label actually differs from label are written, so that
// re-running this on an already correctly labeled tree is a read-only, low-cost no-op - both to
// avoid needless filesystem transactions and to avoid wearing down flash media.
//
// onRelabel, if non-nil, is invoked synchronously for every entry that gets relabeled, with its
// path and the label it had before the change; callers can use it to stream progress into a log
// without having to buffer the (potentially very large) list of changed paths in memory.
func SetLabelRecursive(dir string, label string, skipPaths []string, onRelabel func(path, oldLabel string), excludeLabels ...string) (RelabelStats, error) {
	var stats RelabelStats

	if label == "" || !IsEnabled() {
		return stats, nil
	}

	skip := make(map[string]struct{}, len(skipPaths))
	for _, p := range skipPaths {
		skip[filepath.Clean(p)] = struct{}{}
	}

	rootDev, err := deviceOf(dir)
	if err != nil {
		return stats, err
	}

	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() && path != dir {
			if _, ok := skip[filepath.Clean(path)]; ok {
				// a nested volume with its own label lives here - never overwrite it.
				return filepath.SkipDir
			}

			if dev, devErr := deviceOf(path); devErr == nil && dev != rootDev {
				// a different filesystem is mounted here - it gets relabeled on its own.
				return filepath.SkipDir
			}
		}

		stats.Scanned++

		current, err := GetLabel(path)
		if err != nil {
			return err
		}

		if current == label || (current != "" && slices.Contains(excludeLabels, current)) {
			return nil
		}

		if err := SetLabel(path, label, excludeLabels...); err != nil {
			return err
		}

		stats.Relabeled++

		if onRelabel != nil {
			onRelabel(path, current)
		}

		return nil
	})

	return stats, err
}

// deviceOf returns the device number of the filesystem containing path, without following
// symlinks, so that callers can detect a mount-point boundary while walking a tree.
func deviceOf(path string) (uint64, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}

	sysStat, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("unsupported stat_t for %q", path)
	}

	return uint64(sysStat.Dev), nil
}

// Init initializes SELinux based on the configured mode.
// It loads the policy and enforces it if necessary.
func Init() error {
	if !IsEnabled() {
		log.Println("selinux: disabled, not loading policy")

		return nil
	}

	if IsEnforcing() {
		log.Println("selinux: running in enforcing mode, policy will be applied as soon as it's loaded")
	}

	log.Println("selinux: loading policy")

	if err := os.WriteFile("/sys/fs/selinux/load", policy, 0o777); err != nil {
		return err
	}

	log.Println("selinux: policy loaded")

	return nil
}
