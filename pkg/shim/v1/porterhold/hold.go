// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package porterhold is a shim extension that holds a container in the created
// state: it creates the container normally (booting the sentry for a sandbox
// root) but does not run its guest process on Start. It exists to test whether
// a gVisor sandbox can be kept warm-but-unstarted under kubelet/containerd, so
// a checkpoint can later be restored into it (restore requires the Created
// state). Only pods annotated dev.porter.hold-created=true are held.
package porterhold

import (
	"context"

	task "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/log"

	"gvisor.dev/gvisor/pkg/shim/v1/extension"
	"gvisor.dev/gvisor/pkg/shim/v1/utils"
)

// holdAnnotation marks a pod whose containers should be created but not started.
const holdAnnotation = "dev.porter.hold-created"

// New is installed as extension.NewExtension. It returns a holding extension
// for containers in an annotated pod, and nil (pass-through) otherwise.
func New(ctx context.Context, next extension.TaskServiceExt, req *task.CreateTaskRequest) (extension.TaskServiceExt, error) {
	spec, err := utils.ReadSpec(req.Bundle)
	if err != nil {
		return nil, nil
	}
	if spec.Annotations[holdAnnotation] != "true" {
		return nil, nil
	}
	log.L.Infof("porterhold: holding container %q in created state", req.ID)
	return &holdExt{TaskServiceExt: next, next: next}, nil
}

// holdExt wraps the base task service, passing every call through except the
// init process's Start, which it turns into a no-op so the guest never runs and
// the container stays in the Created state.
type holdExt struct {
	extension.TaskServiceExt
	next extension.TaskServiceExt
}

// Start acknowledges the init process's start without running it, leaving the
// container Created. Exec starts (non-empty ExecID) pass through.
func (h *holdExt) Start(ctx context.Context, r *task.StartRequest) (*task.StartResponse, error) {
	if len(r.ExecID) != 0 {
		return h.next.Start(ctx, r)
	}
	pid := uint32(0)
	if st, err := h.next.State(ctx, &task.StateRequest{ID: r.ID}); err == nil {
		pid = st.Pid
	}
	log.L.Infof("porterhold: no-op Start for %q, reporting created pid %d", r.ID, pid)
	return &task.StartResponse{Pid: pid}, nil
}
