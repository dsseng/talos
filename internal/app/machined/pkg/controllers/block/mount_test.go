// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package block_test

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cosi-project/runtime/pkg/state"
	"github.com/siderolabs/go-retry/retry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/unix"

	blockctrls "github.com/siderolabs/talos/internal/app/machined/pkg/controllers/block"
	"github.com/siderolabs/talos/internal/app/machined/pkg/controllers/ctest"
	"github.com/siderolabs/talos/pkg/machinery/constants"
	"github.com/siderolabs/talos/pkg/machinery/resources/block"
)

type MountSuite struct {
	ctest.DefaultSuite
}

func TestMountSuite(t *testing.T) {
	t.Parallel()

	suite.Run(t, &MountSuite{
		Timeout: 3 * time.Second,
		AfterSetup: func(suite *ctest.DefaultSuite) {
			suite.Require().NoError(suite.Runtime().RegisterController(&blockctrls.MountController{}))
		},
	})
}

func (suite *MountSuite) mountVolume(volumeID string) {
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

func (suite *MountSuite) TestUserVolumeMountPointCleanup() {
	dir := suite.T().TempDir()

	// leftover empty mount point
	suite.Require().NoError(os.Mkdir(filepath.Join(dir, "empty"), 0o755))
	// non-empty directory
	suite.Require().NoError(os.Mkdir(filepath.Join(dir, "data"), 0o755))
	suite.Require().NoError(os.WriteFile(filepath.Join(dir, "data", "file"), []byte("data"), 0o644))
	// regular file
	suite.Require().NoError(os.WriteFile(filepath.Join(dir, "file"), []byte("data"), 0o644))

	volumeStatus := block.NewVolumeStatus(block.NamespaceName, constants.UserVolumeMountPoint)
	volumeStatus.TypedSpec().Type = block.VolumeTypeDirectory
	volumeStatus.TypedSpec().MountSpec = block.MountSpec{
		TargetPath: dir,
		FileMode:   0o755,
		UID:        os.Getuid(),
		GID:        os.Getgid(),
	}
	volumeStatus.TypedSpec().Phase = block.VolumePhaseReady
	suite.Create(volumeStatus)

	suite.mountVolume(constants.UserVolumeMountPoint)

	suite.Assert().NoDirExists(filepath.Join(dir, "empty"))
	suite.Assert().FileExists(filepath.Join(dir, "data", "file"))
	suite.Assert().FileExists(filepath.Join(dir, "file"))
}

func (suite *MountSuite) TestMemoryMountRequiresSize() {
	dir := suite.T().TempDir()
	targetPath := filepath.Join(dir, "memory-target")

	volumeStatus := block.NewVolumeStatus(block.NamespaceName, "memory-volume")
	volumeStatus.TypedSpec().Type = block.VolumeTypeTmpfs
	volumeStatus.TypedSpec().MountSpec = block.MountSpec{
		TargetPath: targetPath,
	}
	volumeStatus.TypedSpec().Phase = block.VolumePhaseReady
	suite.Create(volumeStatus)

	mountRequest := block.NewMountRequest(block.NamespaceName, "memory-volume")
	mountRequest.TypedSpec().RequesterIDs = []string{"requester1/memory-volume"}
	mountRequest.TypedSpec().Requesters = []string{"requester1"}
	mountRequest.TypedSpec().VolumeID = "memory-volume"
	suite.Create(mountRequest)

	ctest.AssertNoResource[*block.MountStatus](suite, "memory-volume")

	_, err := os.Stat(targetPath)
	suite.Require().Error(err)
	suite.Require().True(os.IsNotExist(err))
}

// requireRoot skips the test unless it can perform real mounts.
func (suite *MountSuite) requireRoot() {
	if os.Geteuid() != 0 {
		suite.T().Skip("skipping test; must be root to mount tmpfs")
	}
}

// createMemoryVolume creates a ready memory volume with the given tmpfs size limit.
func (suite *MountSuite) createMemoryVolume(volumeID, target string, size uint64) {
	// make sure a failed test doesn't leave a mount behind
	suite.T().Cleanup(func() {
		unix.Unmount(target, unix.MNT_DETACH) //nolint:errcheck
	})

	volumeStatus := block.NewVolumeStatus(block.NamespaceName, volumeID)
	volumeStatus.TypedSpec().Type = block.VolumeTypeTmpfs
	volumeStatus.TypedSpec().MountSpec = block.MountSpec{
		TargetPath: target,
		FileMode:   0o755,
		Parameters: []block.ParameterSpec{
			{
				Type:   block.FSParameterTypeStringValue,
				Name:   "size",
				String: new(strconv.FormatUint(size, 10)),
			},
		},
	}
	volumeStatus.TypedSpec().Phase = block.VolumePhaseReady
	suite.Create(volumeStatus)
}

func (suite *MountSuite) createMountRequest(volumeID string, mutate func(*block.MountRequestSpec)) *block.MountRequest {
	mountRequest := block.NewMountRequest(block.NamespaceName, volumeID)
	mountRequest.TypedSpec().RequesterIDs = []string{"requester1/" + volumeID}
	mountRequest.TypedSpec().Requesters = []string{"requester1"}
	mountRequest.TypedSpec().VolumeID = volumeID

	if mutate != nil {
		mutate(mountRequest.TypedSpec())
	}

	suite.Create(mountRequest)

	ctest.AssertResource(suite, volumeID, func(*block.MountStatus, *assert.Assertions) {})

	return mountRequest
}

// unmountVolume tears down the mount request and waits for the controller to unmount the volume.
func (suite *MountSuite) unmountVolume(mountRequest *block.MountRequest) {
	_, err := suite.State().Teardown(suite.Ctx(), mountRequest.Metadata())
	suite.Require().NoError(err)

	_, err = suite.State().WatchFor(suite.Ctx(), mountRequest.Metadata(), state.WithFinalizerEmpty())
	suite.Require().NoError(err)

	suite.Destroy(mountRequest)
}

type statfsInfo struct {
	tmpfs bool
	size  uint64
	flags int64
}

func statfs(t *testing.T, path string) statfsInfo {
	t.Helper()

	var st unix.Statfs_t

	require := assert.New(t)
	require.NoError(unix.Statfs(path, &st))

	return statfsInfo{
		tmpfs: st.Type == unix.TMPFS_MAGIC,
		size:  uint64(st.Blocks) * uint64(st.Bsize), //nolint:gosec
		flags: int64(st.Flags),                      //nolint:gosec
	}
}

func (suite *MountSuite) TestMemoryMount() {
	suite.requireRoot()

	const size = 8 * 1024 * 1024

	// the mount point doesn't exist, and is created for the mount
	target := filepath.Join(suite.T().TempDir(), "nested", "memory-target")

	suite.createMemoryVolume("memory-volume", target, size)

	mountRequest := suite.createMountRequest("memory-volume", nil)

	info := statfs(suite.T(), target)
	suite.Assert().True(info.tmpfs, "target should be a tmpfs")
	suite.Assert().Equal(uint64(size), info.size)
	suite.Assert().Zero(info.flags&unix.ST_RDONLY, "mount should be writable")

	suite.Require().NoError(os.WriteFile(filepath.Join(target, "file"), []byte("data"), 0o644))

	suite.unmountVolume(mountRequest)

	// the mount point created for the volume is gone, and the content with it
	suite.Assert().NoDirExists(target)
}

func (suite *MountSuite) TestMemoryMountSecurity() {
	suite.requireRoot()

	target := filepath.Join(suite.T().TempDir(), "memory-target")

	suite.createMemoryVolume("memory-volume", target, 4*1024*1024)

	mountRequest := suite.createMountRequest("memory-volume", func(spec *block.MountRequestSpec) {
		spec.Secure = true
		spec.NoExec = true
	})

	info := statfs(suite.T(), target)
	suite.Assert().True(info.tmpfs)
	suite.Assert().NotZero(info.flags&unix.ST_NOSUID, "nosuid expected")
	suite.Assert().NotZero(info.flags&unix.ST_NODEV, "nodev expected")
	suite.Assert().NotZero(info.flags&unix.ST_NOEXEC, "noexec expected")

	// relax the security options on the live mount
	ctest.UpdateWithConflicts(suite, mountRequest, func(r *block.MountRequest) error {
		r.TypedSpec().Secure = false
		r.TypedSpec().NoExec = false

		return nil
	})

	suite.AssertWithin(5*time.Second, 50*time.Millisecond, func() error {
		info = statfs(suite.T(), target)

		if info.flags&(unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC) != 0 {
			return retry.ExpectedError(assert.AnError)
		}

		return nil
	})

	suite.unmountVolume(mountRequest)
}

func (suite *MountSuite) TestMemoryMountReadOnlyRemount() {
	suite.requireRoot()

	target := filepath.Join(suite.T().TempDir(), "memory-target")

	suite.createMemoryVolume("memory-volume", target, 4*1024*1024)

	mountRequest := suite.createMountRequest("memory-volume", nil)

	suite.Require().NoError(os.WriteFile(filepath.Join(target, "file"), []byte("data"), 0o644))

	// seal the volume once it is populated
	ctest.UpdateWithConflicts(suite, mountRequest, func(r *block.MountRequest) error {
		r.TypedSpec().ReadOnly = true

		return nil
	})

	suite.AssertWithin(5*time.Second, 50*time.Millisecond, func() error {
		if statfs(suite.T(), target).flags&unix.ST_RDONLY == 0 {
			return retry.ExpectedError(assert.AnError)
		}

		return nil
	})

	// the content survives the remount, but can't be changed
	data, err := os.ReadFile(filepath.Join(target, "file"))
	suite.Require().NoError(err)
	suite.Assert().Equal("data", string(data))
	suite.Assert().Error(os.WriteFile(filepath.Join(target, "other"), []byte("data"), 0o644))

	suite.unmountVolume(mountRequest)
}

func (suite *MountSuite) TestMemoryMountDetached() {
	suite.requireRoot()

	target := filepath.Join(suite.T().TempDir(), "memory-target")

	suite.createMemoryVolume("memory-volume", target, 4*1024*1024)

	mountRequest := suite.createMountRequest("memory-volume", func(spec *block.MountRequestSpec) {
		spec.Detached = true
	})

	// a detached mount is not attached to the mount tree, and doesn't create its target
	suite.Assert().NoDirExists(target)

	suite.unmountVolume(mountRequest)

	suite.Assert().NoDirExists(target)
}

func (suite *MountSuite) TestMemoryMountIsEmptyAfterRemount() {
	suite.requireRoot()

	target := filepath.Join(suite.T().TempDir(), "memory-target")

	suite.createMemoryVolume("memory-volume", target, 4*1024*1024)

	mountRequest := suite.createMountRequest("memory-volume", nil)

	suite.Require().NoError(os.WriteFile(filepath.Join(target, "file"), []byte("data"), 0o644))

	suite.unmountVolume(mountRequest)

	// a volume has no backing store: once unmounted, its content is gone for good
	mountRequest = suite.createMountRequest("memory-volume", nil)

	entries, err := os.ReadDir(target)
	suite.Require().NoError(err)
	suite.Assert().Empty(entries)

	suite.unmountVolume(mountRequest)
}

func (suite *MountSuite) TestVolumeTypeChangeUnmounts() {
	suite.requireRoot()

	target := filepath.Join(suite.T().TempDir(), "memory-target")

	suite.createMemoryVolume("volume1", target, 4*1024*1024)

	mountRequest := suite.createMountRequest("volume1", nil)

	suite.Require().True(statfs(suite.T(), target).tmpfs)
	suite.Require().NoError(os.WriteFile(filepath.Join(target, "file"), []byte("data"), 0o644))

	// the volume is now a plain directory, e.g. as a result of the configuration being replaced:
	// the tmpfs must not be left mounted at the target of a volume which is not backed by it anymore
	ctest.UpdateWithConflicts(suite, block.NewVolumeStatus(block.NamespaceName, "volume1"), func(r *block.VolumeStatus) error {
		r.TypedSpec().Type = block.VolumeTypeDirectory
		r.TypedSpec().MountSpec.Parameters = nil

		return nil
	})

	suite.AssertWithin(5*time.Second, 50*time.Millisecond, func() error {
		if statfs(suite.T(), target).tmpfs {
			return retry.ExpectedError(assert.AnError)
		}

		return nil
	})

	suite.Assert().DirExists(target)
	suite.Assert().NoFileExists(filepath.Join(target, "file"))

	suite.unmountVolume(mountRequest)
}
