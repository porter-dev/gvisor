// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runsc

import (
	"context"
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	api "github.com/containerd/containerd/api/runtime/sandbox/v1"
	task "github.com/containerd/containerd/api/runtime/task/v2"
	apitypes "github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/v2/pkg/protobuf"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"github.com/containerd/typeurl/v2"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/types/known/anypb"

	"gvisor.dev/gvisor/pkg/shim/v1/extension"
	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
	"gvisor.dev/gvisor/pkg/shim/v1/runtimeoptions"
	"gvisor.dev/gvisor/pkg/shim/v1/utils"
)

// PodSandboxConfig protobuf field numbers used to pull the cgroup parent out of
// the CreateSandbox options without depending on the k8s CRI API types.
//  - linuxPodConfigField is PodSandboxConfig.linux.
//  - cgroupParentField is LinuxPodSandboxConfig.cgroup_parent.
const (
	linuxPodConfigField = 8
	cgroupParentField   = 1
)

// runscOptionsType is the type url stored inside the runtime options; it names
// the format of the shim config file that ConfigPath points at.
const runscOptionsType = "io.containerd.runsc.v1.options"

// sandboxConfigPaths are the shim config file locations, in priority order.
// The sandbox root must boot with the same runsc root and flags the workload
// containers will use, so it reads the same file the runtime's ConfigPath
// points at. /etc/containerd/runsc.toml is the CRI runtime's configured path;
// the rest match GetRuntimeOptions' search.
var sandboxConfigPaths = []string{
	"/etc/containerd/runsc.toml",
	"/run/containerd/runsc/config.toml",
	"/etc/containerd/runsc/config.toml",
	"config.toml",
}

// CreateSandbox boots an empty warm sentry for the pod: it synthesizes a
// minimal sandbox-root OCI spec joined to the pod's network namespace and
// creates it, leaving the root process in the Created state (guest never run).
// The sentry is up and joined to the netns; a later claim starts the real
// workload or restores a checkpoint into it.
func (s *runscService) CreateSandbox(ctx context.Context, req *api.CreateSandboxRequest) (*api.CreateSandboxResponse, error) {
	log.L.Infof("CreateSandbox %q, netns %q", req.SandboxID, req.NetnsPath)

	cgroupsPath := sandboxCgroupsPath(cgroupParentFromOptions(req.Options), req.SandboxID)
	spec := buildSandboxSpec(req.SandboxID, req.NetnsPath, cgroupsPath)
	if err := os.MkdirAll(req.BundlePath, 0711); err != nil {
		return nil, fmt.Errorf("create sandbox bundle: %w", err)
	}
	if err := utils.WriteSpec(req.BundlePath, spec); err != nil {
		return nil, fmt.Errorf("write sandbox spec: %w", err)
	}

	opts, err := sandboxRuntimeOptions()
	if err != nil {
		return nil, err
	}
	if _, err := s.CreateWithFSRestore(ctx, &extension.CreateWithFSRestoreRequest{
		Create: &task.CreateTaskRequest{
			ID:      req.SandboxID,
			Bundle:  req.BundlePath,
			Options: opts,
		},
	}); err != nil {
		return nil, fmt.Errorf("create sandbox %q: %w", req.SandboxID, err)
	}
	return &api.CreateSandboxResponse{}, nil
}

// StartSandbox reports the warm sentry as up. The root process is deliberately
// left Created, so the sentry stays restore-ready; container routing uses the
// shim's own bootstrap endpoint, so only the pid is reported here.
func (s *runscService) StartSandbox(ctx context.Context, req *api.StartSandboxRequest) (*api.StartSandboxResponse, error) {
	c, err := s.getContainer(req.SandboxID)
	if err != nil {
		return nil, err
	}
	pid := c.task.Pid()
	log.L.Infof("StartSandbox %q, sentry pid %d (root held created)", req.SandboxID, pid)
	return &api.StartSandboxResponse{
		Pid:       uint32(pid),
		CreatedAt: protobuf.ToTimestamp(time.Now()),
	}, nil
}

// WaitSandbox blocks until the warm sentry exits and returns its exit status.
// This is the only signal that flips the pod to NOTREADY, so it resolves only
// on real sentry death.
func (s *runscService) WaitSandbox(ctx context.Context, req *api.WaitSandboxRequest) (*api.WaitSandboxResponse, error) {
	c, err := s.getContainer(req.SandboxID)
	if err != nil {
		return nil, err
	}
	c.task.Wait()
	return &api.WaitSandboxResponse{
		ExitStatus: uint32(c.task.ExitStatus()),
		ExitedAt:   protobuf.ToTimestamp(c.task.ExitedAt()),
	}, nil
}

// SandboxStatus reports the sandbox as ready while its sentry is alive.
func (s *runscService) SandboxStatus(ctx context.Context, req *api.SandboxStatusRequest) (*api.SandboxStatusResponse, error) {
	c, err := s.getContainer(req.SandboxID)
	if err != nil {
		return nil, err
	}
	runscStatus, err := c.task.Status(ctx)
	if err != nil {
		return nil, err
	}
	state := "SANDBOX_READY"
	if runscStatus == "stopped" {
		state = "SANDBOX_NOTREADY"
	}
	resp := &api.SandboxStatusResponse{
		SandboxID: req.SandboxID,
		Pid:       uint32(c.task.Pid()),
		State:     state,
		CreatedAt: protobuf.ToTimestamp(time.Now()),
	}
	if req.Verbose {
		resp.Info = map[string]string{"runsc_status": runscStatus}
	}
	return resp, nil
}

// StopSandbox kills the warm sentry, which resolves WaitSandbox.
func (s *runscService) StopSandbox(ctx context.Context, req *api.StopSandboxRequest) (*api.StopSandboxResponse, error) {
	c, err := s.getContainer(req.SandboxID)
	if err != nil {
		// Already gone; stop is idempotent.
		return &api.StopSandboxResponse{}, nil
	}
	log.L.Infof("StopSandbox %q", req.SandboxID)
	if err := c.task.Runtime().Kill(ctx, req.SandboxID, int(unix.SIGKILL), &runsccmd.KillOpts{All: true}); err != nil {
		log.L.Warningf("StopSandbox: killing sentry: %v", err)
	}
	return &api.StopSandboxResponse{}, nil
}

// ShutdownSandbox deletes the sentry from disk and shuts the shim down.
func (s *runscService) ShutdownSandbox(ctx context.Context, req *api.ShutdownSandboxRequest) (*api.ShutdownSandboxResponse, error) {
	log.L.Infof("ShutdownSandbox %q", req.SandboxID)
	if c, err := s.getContainer(req.SandboxID); err == nil {
		if err := c.task.Runtime().Delete(ctx, req.SandboxID, &runsccmd.DeleteOpts{Force: true}); err != nil {
			log.L.Warningf("ShutdownSandbox: deleting sentry: %v", err)
		}
	}
	s.shutdown.Shutdown()
	return &api.ShutdownSandboxResponse{}, nil
}

// Platform reports the host platform the sandbox runs containers on.
func (s *runscService) Platform(ctx context.Context, req *api.PlatformRequest) (*api.PlatformResponse, error) {
	return &api.PlatformResponse{
		Platform: &apitypes.Platform{OS: "linux", Architecture: runtime.GOARCH},
	}, nil
}

// PingSandbox acknowledges the shim is alive.
func (s *runscService) PingSandbox(ctx context.Context, req *api.PingRequest) (*api.PingResponse, error) {
	return &api.PingResponse{}, nil
}

// SandboxMetrics is not implemented; zeroed metrics are acceptable.
func (s *runscService) SandboxMetrics(ctx context.Context, req *api.SandboxMetricsRequest) (*api.SandboxMetricsResponse, error) {
	return nil, errdefs.ErrNotImplemented
}

// buildSandboxSpec synthesizes a minimal OCI spec for an empty gVisor sandbox
// root joined to netnsPath. The process is never started, so an empty rootfs
// and placeholder args suffice; the container-type annotation marks it a
// sandbox so runsc boots a sentry.
func buildSandboxSpec(id, netnsPath, cgroupsPath string) *specs.Spec {
	namespaces := []specs.LinuxNamespace{
		{Type: specs.PIDNamespace},
		{Type: specs.IPCNamespace},
		{Type: specs.UTSNamespace},
		{Type: specs.MountNamespace},
	}
	if netnsPath != "" {
		namespaces = append(namespaces, specs.LinuxNamespace{Type: specs.NetworkNamespace, Path: netnsPath})
	} else {
		namespaces = append(namespaces, specs.LinuxNamespace{Type: specs.NetworkNamespace})
	}
	return &specs.Spec{
		Version:  specs.Version,
		Hostname: id,
		Root:     &specs.Root{Path: "rootfs"},
		Process: &specs.Process{
			Args: []string{"/pause"},
			Cwd:  "/",
		},
		Annotations: map[string]string{
			utils.ContainerTypeAnnotation: "sandbox",
		},
		Mounts: []specs.Mount{
			{Destination: "/proc", Type: "proc", Source: "proc"},
			{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
			{Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}},
			{Destination: "/dev/shm", Type: "tmpfs", Source: "shm", Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}},
			{Destination: "/dev/mqueue", Type: "mqueue", Source: "mqueue", Options: []string{"nosuid", "noexec", "nodev"}},
			{Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}},
		},
		Linux: &specs.Linux{
			Namespaces:  namespaces,
			CgroupsPath: cgroupsPath,
		},
	}
}

// sandboxCgroupsPath builds the sandbox's cgroup path from the pod's cgroup
// parent, matching containerd's getCgroupsPath: a systemd slice parent yields
// the "slice:prefix:id" form runsc expects under systemd-cgroup, otherwise a
// joined filesystem path. Empty parent yields empty (runsc default).
func sandboxCgroupsPath(cgroupParent, id string) string {
	if cgroupParent == "" {
		return ""
	}
	base := path.Base(cgroupParent)
	if strings.HasSuffix(base, ".slice") {
		return strings.Join([]string{base, "cri-containerd", id}, ":")
	}
	return path.Join(cgroupParent, id)
}

// cgroupParentFromOptions pulls PodSandboxConfig.linux.cgroup_parent out of the
// CreateSandbox options blob by walking the protobuf wire format, avoiding a
// dependency on the k8s CRI API types.
func cgroupParentFromOptions(opts *anypb.Any) string {
	if opts == nil {
		return ""
	}
	linux := protoBytesField(opts.GetValue(), linuxPodConfigField)
	if linux == nil {
		return ""
	}
	return string(protoBytesField(linux, cgroupParentField))
}

// protoBytesField returns the value of the first length-delimited field with
// the given number in a protobuf-encoded message, or nil if absent.
func protoBytesField(b []byte, field protowire.Number) []byte {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil
		}
		b = b[n:]
		if num == field && typ == protowire.BytesType {
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return nil
			}
			return v
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return nil
		}
		b = b[m:]
	}
	return nil
}

// sandboxRuntimeOptions builds the runtime options carrying the shim config
// path, so the sandbox root boots under the same runsc root and flags as the
// workload containers that will join it.
func sandboxRuntimeOptions() (*anypb.Any, error) {
	opts := &runtimeoptions.Options{TypeUrl: runscOptionsType, ConfigPath: DefaultShimConfigPath()}
	any, err := typeurl.MarshalAnyToProto(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal runtime options: %w", err)
	}
	return any, nil
}

// DefaultShimConfigPath returns the first shim config file that exists, or empty
// if none. It backstops the config path when containerd does not carry a runsc
// ConfigPath in the task options — as in sandboxer=shim mode, where containerd
// (2.2.x) forces runc-typed task options onto the joining containers.
func DefaultShimConfigPath() string {
	for _, p := range sandboxConfigPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
