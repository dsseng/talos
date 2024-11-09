// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package filetree

import (
	"io/fs"
	"path/filepath"

	"github.com/siderolabs/talos/internal/pkg/selinux"
)

// RelabelRecursive changes file SELinux labels recursively from the specified root.
func RelabelRecursive(root, label string) error {
	return filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		return selinux.SetLabel(path, label)
	})
}
