// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package block_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	blockctrls "github.com/siderolabs/talos/internal/app/machined/pkg/controllers/block"
	"github.com/siderolabs/talos/internal/app/machined/pkg/controllers/ctest"
	"github.com/siderolabs/talos/internal/pkg/selinux"
	"github.com/siderolabs/talos/pkg/machinery/resources/block"
)

type MountSuite struct {
	ctest.DefaultSuite
}

func TestMountSuite(t *testing.T) {
	t.Parallel()

	suite.Run(t, &MountSuite{
		DefaultSuite: ctest.DefaultSuite{
			Timeout: 3 * time.Second,
			AfterSetup: func(suite *ctest.DefaultSuite) {
				suite.Require().NoError(suite.Runtime().RegisterController(&blockctrls.MountController{}))
			},
		},
	})
}

func (suite *MountSuite) mountVolume(volumeID string) { //nolint:unparam
	mountRequest := block.NewMountRequest(block.NamespaceName, volumeID)
	mountRequest.TypedSpec().RequesterIDs = []string{"requester1/" + volumeID}
	mountRequest.TypedSpec().Requesters = []string{"requester1"}
	mountRequest.TypedSpec().VolumeID = volumeID
	suite.Create(mountRequest)

	// wait for the mount status to be created
	ctest.AssertResource(suite, volumeID, func(*block.MountStatus, *assert.Assertions) {})
}

func (suite *MountSuite) TestSymlinkNew() {
	dir := suite.T().TempDir()
	targetPath := filepath.Join(dir, "target")

	volumeStatus := block.NewVolumeStatus(block.NamespaceName, "volume1")
	volumeStatus.TypedSpec().Type = block.VolumeTypeSymlink
	volumeStatus.TypedSpec().SymlinkSpec = block.SymlinkProvisioningSpec{
		SymlinkTargetPath: "/run",
		Force:             true,
	}
	volumeStatus.TypedSpec().MountSpec = block.MountSpec{
		TargetPath: targetPath,
	}
	volumeStatus.TypedSpec().Phase = block.VolumePhaseReady
	suite.Create(volumeStatus)

	suite.mountVolume("volume1")

	// verify symlink
	path, err := os.Readlink(targetPath)
	suite.Require().NoError(err)
	suite.Assert().Equal("/run", path)
}

func (suite *MountSuite) TestSymlinkExists() {
	dir := suite.T().TempDir()
	targetPath := filepath.Join(dir, "target")

	// symlink already exists
	suite.Require().NoError(os.Symlink("/run", targetPath))

	volumeStatus := block.NewVolumeStatus(block.NamespaceName, "volume1")
	volumeStatus.TypedSpec().Type = block.VolumeTypeSymlink
	volumeStatus.TypedSpec().SymlinkSpec = block.SymlinkProvisioningSpec{
		SymlinkTargetPath: "/run",
	}
	volumeStatus.TypedSpec().MountSpec = block.MountSpec{
		TargetPath: targetPath,
	}
	volumeStatus.TypedSpec().Phase = block.VolumePhaseReady
	suite.Create(volumeStatus)

	suite.mountVolume("volume1")

	// verify symlink
	path, err := os.Readlink(targetPath)
	suite.Require().NoError(err)
	suite.Assert().Equal("/run", path)
}

func (suite *MountSuite) TestSymlinkWrong() {
	dir := suite.T().TempDir()
	targetPath := filepath.Join(dir, "target")

	// wrong symlink target
	suite.Require().NoError(os.Symlink("/foo", targetPath))

	volumeStatus := block.NewVolumeStatus(block.NamespaceName, "volume1")
	volumeStatus.TypedSpec().Type = block.VolumeTypeSymlink
	volumeStatus.TypedSpec().SymlinkSpec = block.SymlinkProvisioningSpec{
		SymlinkTargetPath: "/run",
		Force:             true,
	}
	volumeStatus.TypedSpec().MountSpec = block.MountSpec{
		TargetPath: targetPath,
	}
	volumeStatus.TypedSpec().Phase = block.VolumePhaseReady
	suite.Create(volumeStatus)

	suite.mountVolume("volume1")

	// verify symlink
	path, err := os.Readlink(targetPath)
	suite.Require().NoError(err)
	suite.Assert().Equal("/run", path)
}

func (suite *MountSuite) TestSymlinkDirectory() {
	dir := suite.T().TempDir()
	targetPath := filepath.Join(dir, "target")

	// non-empty directory structure
	suite.Require().NoError(os.Mkdir(targetPath, 0o755))
	suite.Require().NoError(os.Mkdir(filepath.Join(targetPath, "foo"), 0o755))

	volumeStatus := block.NewVolumeStatus(block.NamespaceName, "volume1")
	volumeStatus.TypedSpec().Type = block.VolumeTypeSymlink
	volumeStatus.TypedSpec().SymlinkSpec = block.SymlinkProvisioningSpec{
		SymlinkTargetPath: "/run",
		Force:             true,
	}
	volumeStatus.TypedSpec().MountSpec = block.MountSpec{
		TargetPath: targetPath,
	}
	volumeStatus.TypedSpec().Phase = block.VolumePhaseReady
	suite.Create(volumeStatus)

	suite.mountVolume("volume1")

	// verify symlink
	path, err := os.Readlink(targetPath)
	suite.Require().NoError(err)
	suite.Assert().Equal("/run", path)
}

// TestSELinuxRelabelSkipsNestedVolume is a regression test: a RecursiveRelabel mount must not
// stomp the label of a nested child volume mounted directly under it, even on the very first
// activation - before the child's own MountStatus exists. The exclusion list has to come from
// VolumeStatus (available immediately), not from MountStatus/MountRequest (which, for a child,
// only exists after the parent is already mounted - i.e. always one reconcile too late on a fresh
// boot, which previously caused every such parent to be spuriously relabeled on every boot).
func (suite *MountSuite) TestSELinuxRelabelSkipsNestedVolume() {
	originalIsEnabled := selinux.IsEnabled
	selinux.IsEnabled = func() bool { return true }

	suite.T().Cleanup(func() { selinux.IsEnabled = originalIsEnabled })

	const (
		parentLabel = "system_u:object_r:parent_t:s0"
		childLabel  = "system_u:object_r:child_t:s0"
	)

	dir := suite.T().TempDir()
	parentDir := filepath.Join(dir, "parent")
	childDir := filepath.Join(parentDir, "child")

	suite.Require().NoError(os.MkdirAll(childDir, 0o755))

	// Simulate content left over from previous boots: the parent tree has one correctly labeled
	// file and one genuinely mislabeled file (so a real repair pass is actually triggered, not
	// just a no-op spot-check), plus the nested child volume, already correctly labeled with its
	// own, different label.
	parentFile := filepath.Join(parentDir, "file")
	suite.Require().NoError(os.WriteFile(parentFile, nil, 0o644))
	suite.Require().NoError(selinux.SetLabel(parentDir, parentLabel))
	suite.Require().NoError(selinux.SetLabel(parentFile, parentLabel))

	staleFile := filepath.Join(parentDir, "stale")
	suite.Require().NoError(os.WriteFile(staleFile, nil, 0o644))
	suite.Require().NoError(selinux.SetLabel(staleFile, "system_u:object_r:stale_t:s0"))

	childFile := filepath.Join(childDir, "file")
	suite.Require().NoError(os.WriteFile(childFile, nil, 0o644))
	suite.Require().NoError(selinux.SetLabel(childDir, childLabel))
	suite.Require().NoError(selinux.SetLabel(childFile, childLabel))

	parentVolume := block.NewVolumeStatus(block.NamespaceName, "parent1")
	parentVolume.TypedSpec().Type = block.VolumeTypeDirectory
	parentVolume.TypedSpec().MountSpec = block.MountSpec{
		TargetPath:       parentDir,
		SelinuxLabel:     parentLabel,
		FileMode:         0o755,
		RecursiveRelabel: true,
	}
	parentVolume.TypedSpec().Phase = block.VolumePhaseReady
	suite.Create(parentVolume)

	childVolume := block.NewVolumeStatus(block.NamespaceName, "child1")
	childVolume.TypedSpec().Type = block.VolumeTypeDirectory
	childVolume.TypedSpec().MountSpec = block.MountSpec{
		TargetPath:   "child",
		ParentID:     "parent1",
		SelinuxLabel: childLabel,
		FileMode:     0o755,
	}
	childVolume.TypedSpec().Phase = block.VolumePhaseReady
	suite.Create(childVolume)

	// Only mount the parent: this is the scenario that matters, since mounting the child requires
	// the parent to already be mounted and Running, so the parent is always activated first.
	suite.mountVolume("parent1")

	label, err := selinux.GetLabel(childDir)
	suite.Require().NoError(err)
	suite.Assert().Equal(childLabel, label, "the nested child volume's own label must survive the parent's relabel pass")

	label, err = selinux.GetLabel(childFile)
	suite.Require().NoError(err)
	suite.Assert().Equal(childLabel, label, "content under the nested child volume must survive too")

	// sanity: the parent itself is still correctly labeled.
	label, err = selinux.GetLabel(parentDir)
	suite.Require().NoError(err)
	suite.Assert().Equal(parentLabel, label)

	// sanity: a real repair pass did run (the stale file proves it wasn't just a no-op spot-check).
	label, err = selinux.GetLabel(staleFile)
	suite.Require().NoError(err)
	suite.Assert().Equal(parentLabel, label, "the genuinely mislabeled parent-owned file should have been repaired")
}
