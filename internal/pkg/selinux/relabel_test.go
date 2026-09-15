// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package selinux_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/siderolabs/talos/internal/pkg/selinux"
)

// withSELinuxEnabled forces selinux.IsEnabled() to true for the duration of the test, restoring
// the original value on cleanup. This lets the relabel logic be tested without a real SELinux
// kernel/policy, since it only manipulates the security.selinux xattr directly.
func withSELinuxEnabled(t *testing.T) {
	t.Helper()

	original := selinux.IsEnabled

	selinux.IsEnabled = func() bool { return true }
	t.Cleanup(func() { selinux.IsEnabled = original })
}

func getLabel(t *testing.T, path string) string {
	t.Helper()

	label, err := selinux.GetLabel(path)
	require.NoError(t, err)

	return label
}

func TestNeedsRelabel(t *testing.T) {
	withSELinuxEnabled(t)

	const label = "system_u:object_r:test_t:s0"

	t.Run("fresh directory needs relabel", func(t *testing.T) {
		dir := t.TempDir()

		needs, err := selinux.NeedsRelabel(dir, label)
		require.NoError(t, err)
		require.True(t, needs, "an unlabeled directory should be reported as needing a relabel")
	})

	t.Run("correctly labeled directory does not need relabel", func(t *testing.T) {
		dir := t.TempDir()

		require.NoError(t, selinux.SetLabel(dir, label))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "file"), nil, 0o644))
		require.NoError(t, selinux.SetLabel(filepath.Join(dir, "file"), label))

		needs, err := selinux.NeedsRelabel(dir, label)
		require.NoError(t, err)
		require.False(t, needs)
	})

	t.Run("mismatched child triggers relabel", func(t *testing.T) {
		dir := t.TempDir()

		require.NoError(t, selinux.SetLabel(dir, label))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "file"), nil, 0o644))
		require.NoError(t, selinux.SetLabel(filepath.Join(dir, "file"), "system_u:object_r:wrong_t:s0"))

		needs, err := selinux.NeedsRelabel(dir, label)
		require.NoError(t, err)
		require.True(t, needs)
	})

	t.Run("a differently labeled nested volume is skipped", func(t *testing.T) {
		dir := t.TempDir()

		require.NoError(t, selinux.SetLabel(dir, label))

		nested := filepath.Join(dir, "nested")
		require.NoError(t, os.Mkdir(nested, 0o755))
		require.NoError(t, selinux.SetLabel(nested, "system_u:object_r:nested_t:s0"))

		needs, err := selinux.NeedsRelabel(dir, label, nested)
		require.NoError(t, err)
		require.False(t, needs, "a skipped child's own (different) label must not trigger a relabel")
	})

	t.Run("missing directory does not need relabel", func(t *testing.T) {
		needs, err := selinux.NeedsRelabel(filepath.Join(t.TempDir(), "does-not-exist"), label)
		require.NoError(t, err)
		require.False(t, needs)
	})
}

func TestSetLabelRecursive(t *testing.T) {
	withSELinuxEnabled(t)

	const label = "system_u:object_r:test_t:s0"

	t.Run("relabels every entry that differs", func(t *testing.T) {
		dir := t.TempDir()

		sub := filepath.Join(dir, "sub")
		require.NoError(t, os.Mkdir(sub, 0o755))

		file := filepath.Join(sub, "file")
		require.NoError(t, os.WriteFile(file, nil, 0o644))

		alreadyCorrect := filepath.Join(dir, "already-correct")
		require.NoError(t, os.WriteFile(alreadyCorrect, nil, 0o644))
		require.NoError(t, selinux.SetLabel(alreadyCorrect, label))

		stats, err := selinux.SetLabelRecursive(dir, label, nil, nil)
		require.NoError(t, err)

		require.Equal(t, label, getLabel(t, dir))
		require.Equal(t, label, getLabel(t, sub))
		require.Equal(t, label, getLabel(t, file))

		// dir, sub, file were relabeled; already-correct was a no-op write.
		require.Equal(t, 3, stats.Relabeled)
		require.Equal(t, 4, stats.Scanned)
	})

	t.Run("does not descend into a nested volume's mount target", func(t *testing.T) {
		dir := t.TempDir()

		nested := filepath.Join(dir, "nested")
		require.NoError(t, os.Mkdir(nested, 0o755))

		nestedFile := filepath.Join(nested, "file")
		require.NoError(t, os.WriteFile(nestedFile, nil, 0o644))

		const nestedLabel = "system_u:object_r:nested_t:s0"
		require.NoError(t, selinux.SetLabel(nested, nestedLabel))
		require.NoError(t, selinux.SetLabel(nestedFile, nestedLabel))

		_, err := selinux.SetLabelRecursive(dir, label, []string{nested}, nil)
		require.NoError(t, err)

		require.Equal(t, label, getLabel(t, dir))
		require.Equal(t, nestedLabel, getLabel(t, nested), "the nested volume's own label must survive")
		require.Equal(t, nestedLabel, getLabel(t, nestedFile), "content under the nested volume must survive too")
	})

	t.Run("reports every relabeled path via the callback", func(t *testing.T) {
		dir := t.TempDir()

		file := filepath.Join(dir, "file")
		require.NoError(t, os.WriteFile(file, nil, 0o644))

		var relabeled []string

		_, err := selinux.SetLabelRecursive(dir, label, nil, func(path, _ string) {
			relabeled = append(relabeled, path)
		})
		require.NoError(t, err)
		require.ElementsMatch(t, []string{dir, file}, relabeled)
	})

	t.Run("re-running on an already correct tree changes nothing", func(t *testing.T) {
		dir := t.TempDir()

		file := filepath.Join(dir, "file")
		require.NoError(t, os.WriteFile(file, nil, 0o644))

		_, err := selinux.SetLabelRecursive(dir, label, nil, nil)
		require.NoError(t, err)

		stats, err := selinux.SetLabelRecursive(dir, label, nil, nil)
		require.NoError(t, err)
		require.Equal(t, 0, stats.Relabeled, "a second pass over an already correctly labeled tree should not write anything")
	})
}
