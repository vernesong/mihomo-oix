// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package version_test

import (
	"bytes"
	"os"
	"path"
	"runtime/debug"
	"testing"

	ts "github.com/metacubex/tailscale"
	"github.com/metacubex/tailscale/version"
)

func TestAlpineTag(t *testing.T) {
	if tag := readAlpineTag(t, "../Dockerfile.base"); tag == "" {
		t.Fatal(`"FROM alpine:" not found in Dockerfile.base`)
	} else if tag != ts.AlpineDockerTag {
		t.Errorf("alpine version mismatch: Dockerfile.base has %q; ALPINE.txt has %q", tag, ts.AlpineDockerTag)
	}
	if tag := readAlpineTag(t, "../Dockerfile"); tag == "" {
		t.Fatal(`"FROM alpine:" not found in Dockerfile`)
	} else if tag != ts.AlpineDockerTag {
		t.Errorf("alpine version mismatch: Dockerfile has %q; ALPINE.txt has %q", tag, ts.AlpineDockerTag)
	}
}

func readAlpineTag(t *testing.T, file string) string {
	f, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range bytes.Split(f, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		_, suf, ok := bytes.Cut(line, []byte("FROM alpine:"))
		if !ok {
			continue
		}
		return string(suf)
	}
	return ""
}

func TestShortAllocs(t *testing.T) {
	allocs := int(testing.AllocsPerRun(10000, func() {
		_ = version.Short()
	}))
	if allocs > 0 {
		t.Errorf("allocs = %v; want 0", allocs)
	}
}

func BenchmarkCmdName(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = version.CmdName()
	}
}

func BenchmarkReadBuildInfo(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			b.Fatal("ReadBuildInfo failed")
		}
		_ = path.Base(info.Path)
	}
}
