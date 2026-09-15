// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build integration_api

package api

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/siderolabs/go-pointer"
	"github.com/siderolabs/go-procfs/procfs"

	"github.com/siderolabs/talos/cmd/talosctl/pkg/talos/helpers"
	"github.com/siderolabs/talos/internal/integration/base"
	machineapi "github.com/siderolabs/talos/pkg/machinery/api/machine"
	"github.com/siderolabs/talos/pkg/machinery/client"
	"github.com/siderolabs/talos/pkg/machinery/constants"
)

// SELinuxRelabelSuite verifies that Talos detects and repairs SELinux labels on a system volume
// after its content was written to (or corrupted) under a different labeling regime - the
// scenario this covers is an upgrade from a version without SELinux, or from one with a
// different label scheme, as well as any other cause of on-disk label drift.
//
// Since a debug pod running under a normal (unconfined) policy would be denied the
// relabelfrom/relabelto permission needed to corrupt an existing system label under enforcing
// mode, this suite only runs against a permissive-mode cluster (the default for integration
// tests; see base.APISuite.SelinuxEnforcing) - it is exercising the repair mechanism itself, not
// the policy's enforcement of labels, which the negative tests in selinux.go already cover.
type SELinuxRelabelSuite struct {
	base.K8sSuite

	ctx       context.Context //nolint:containedctx
	ctxCancel context.CancelFunc
}

// SuiteName ...
func (suite *SELinuxRelabelSuite) SuiteName() string {
	return "api.SELinuxRelabelSuite"
}

// SetupTest ...
func (suite *SELinuxRelabelSuite) SetupTest() {
	// generous timeout: this test reboots a node and waits for the cluster to become healthy again
	suite.ctx, suite.ctxCancel = context.WithTimeout(context.Background(), 15*time.Minute)

	if suite.Cluster == nil || suite.Cluster.Provisioner() != base.ProvisionerQEMU {
		suite.T().Skip("skipping SELinux relabel test since provisioner is not qemu")
	}

	if suite.SelinuxEnforcing {
		suite.T().Skip("skipping SELinux relabel corruption test in enforcing mode: " +
			"an unconfined debug pod cannot relabel a system path under enforcement")
	}
}

// TearDownTest ...
func (suite *SELinuxRelabelSuite) TearDownTest() {
	if suite.ctxCancel != nil {
		suite.ctxCancel()
	}
}

// readLabel returns the security.selinux xattr value of path on the node addressed by nodeCtx,
// and whether the xattr was present at all.
func (suite *SELinuxRelabelSuite) readLabel(nodeCtx context.Context, path string) (label string, found bool) {
	stream, err := suite.Client.LS(nodeCtx, &machineapi.ListRequest{
		Root:         path,
		ReportXattrs: true,
	})
	suite.Require().NoError(err)

	suite.Require().NoError(helpers.ReadGRPCStream(stream, func(info *machineapi.FileInfo, _ string, _ bool) error {
		if info.Name != path {
			// LS without Recurse also reports path's immediate siblings/children; we only care
			// about the entry for path itself.
			return nil
		}

		for _, x := range info.Xattrs {
			if x.Name == "security.selinux" {
				label = string(bytes.Trim(x.Data, "\x00\n"))
				found = true
			}
		}

		return nil
	}))

	return label, found
}

// TestRelabelAfterCorruption corrupts the SELinux label of the KUBELET system volume (both the
// volume root and a file inside it) from a privileged debug pod, then reboots the node and
// verifies that Talos's boot-time spot-check detects the mismatch and repairs both paths.
func (suite *SELinuxRelabelSuite) TestRelabelAfterCorruption() {
	node := suite.RandomDiscoveredNodeInternalIP()
	nodeCtx := client.WithNode(suite.ctx, node)

	cmdline := suite.ReadCmdline(nodeCtx)

	seLinuxEnabled := pointer.SafeDeref(procfs.NewCmdline(cmdline).Get(constants.KernelParamSELinux).First()) != ""
	if !seLinuxEnabled {
		suite.T().Skip("skipping SELinux relabel test since SELinux is disabled")
	}

	k8sNode, err := suite.GetK8sNodeByInternalIP(suite.ctx, node)
	suite.Require().NoError(err)

	const (
		targetDir    = constants.KubeletDataPath
		markerName   = "selinux-relabel-test-marker"
		corruptLabel = "system_u:object_r:unlabeled_t:s0"
	)

	targetFile := targetDir + "/" + markerName

	// Sanity check: the volume should be correctly labeled before we start corrupting it.
	dirLabelBefore, dirFoundBefore := suite.readLabel(nodeCtx, targetDir)
	suite.Require().True(dirFoundBefore, "expected %s to already carry a security.selinux label", targetDir)
	suite.Require().Equal(constants.KubeletDataSELinuxLabel, dirLabelBefore)

	podDef, err := suite.NewPrivilegedPod("selinux-relabel-corrupt")
	suite.Require().NoError(err)

	podDef = podDef.WithQuiet(true).WithNodeName(k8sNode.Name)

	suite.Require().NoError(podDef.Create(suite.ctx, 5*time.Minute))

	func() {
		defer podDef.Delete(suite.ctx) //nolint:errcheck

		_, stderr, err := podDef.Exec(suite.ctx, "apk add --update attr")
		suite.Require().NoError(err, "stderr: %s", stderr)

		// Simulate content written under a different (or no) SELinux labeling regime: create a
		// new file and force a wrong label onto it and onto the KUBELET volume root itself, via
		// the pod's hostPath bind mount of the whole host filesystem at /host.
		_, stderr, err = podDef.Exec(suite.ctx, fmt.Sprintf(
			"touch /host%[1]s && "+
				"setfattr -n security.selinux -v %[2]q -h /host%[1]s && "+
				"setfattr -n security.selinux -v %[2]q -h /host%[3]s",
			targetFile, corruptLabel, targetDir,
		))
		suite.Require().NoError(err, "stderr: %s", stderr)
	}()

	// Confirm the corruption actually landed before relying on it.
	dirLabel, dirFound := suite.readLabel(nodeCtx, targetDir)
	suite.Require().True(dirFound)
	suite.Require().Equal(corruptLabel, dirLabel, "expected the corrupted label to have been set on %s", targetDir)

	fileLabel, fileFound := suite.readLabel(nodeCtx, targetFile)
	suite.Require().True(fileFound)
	suite.Require().Equal(corruptLabel, fileLabel, "expected the corrupted label to have been set on %s", targetFile)

	// Reboot: this re-activates the KUBELET mount, which runs the boot-time SELinux spot-check
	// (selinux.NeedsRelabel) and, since it finds a mismatch, the recursive repair pass
	// (selinux.SetLabelRecursive), both invoked from block.MountController.updateTargetSettings.
	suite.AssertRebooted(
		suite.ctx, node, func(nodeCtx context.Context) error {
			return base.IgnoreGRPCUnavailable(suite.Client.Reboot(nodeCtx))
		}, 10*time.Minute,
		suite.CleanupFailedPods,
	)

	suite.WaitForBootDone(suite.ctx)

	// The relabel repair runs as part of mounting KUBELET, which happens early in the boot
	// sequence but asynchronously with respect to MachineStageRunning, so poll briefly rather
	// than asserting immediately.
	suite.Require().Eventually(func() bool {
		dirLabel, dirFound := suite.readLabel(nodeCtx, targetDir)
		fileLabel, fileFound := suite.readLabel(nodeCtx, targetFile)

		return dirFound && fileFound &&
			dirLabel == constants.KubeletDataSELinuxLabel &&
			fileLabel == constants.KubeletDataSELinuxLabel
	}, 2*time.Minute, 5*time.Second, "expected SELinux relabel to repair %s and %s after reboot", targetDir, targetFile)

	// Best-effort cleanup of the marker file; the label repair itself is the point of the test,
	// leaving the marker behind is harmless, but keep the volume tidy for any later test.
	cleanupPod, err := suite.NewPrivilegedPod("selinux-relabel-cleanup")
	if suite.Assert().NoError(err) {
		cleanupPod = cleanupPod.WithQuiet(true).WithNodeName(k8sNode.Name)

		if suite.Assert().NoError(cleanupPod.Create(suite.ctx, 5*time.Minute)) {
			_, _, _ = cleanupPod.Exec(suite.ctx, "rm -f /host"+targetFile) //nolint:errcheck

			suite.Assert().NoError(cleanupPod.Delete(suite.ctx))
		}
	}
}

func init() {
	allSuites = append(allSuites, new(SELinuxRelabelSuite))
}
