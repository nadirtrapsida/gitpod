// Copyright (c) 2020 TypeFox GmbH. All rights reserved.
// Licensed under the GNU Affero General Public License (AGPL).
// See License-AGPL.txt in the project root for license information.

package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/containerd/containerd/contrib/seccomp"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func main() {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	spec := specs.Spec{
		Process: &specs.Process{
			Capabilities: &specs.LinuxCapabilities{
				Bounding: os.Args[1:],
			},
		},
	}

	s := seccomp.DefaultProfile(&spec)
	s.Syscalls = append(s.Syscalls, specs.LinuxSyscall{
		Names: []string{
			"clone",
			"mount",
			"chroot",
			"pivot_root",
			"mount",
			"umount2",
		},
		Action: specs.ActAllow,
	})

	err := enc.Encode(s)
	if err != nil {
		log.Fatalf("cannot marshal seccomp profile: %q", err)
	}
}
