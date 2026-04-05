package main

// build_test.go — verifies the codebase compiles cleanly for all release targets.
//
// Skipped in -short mode because cross-compilation can be slow. Each sub-test
// invokes `go build` with the appropriate GOOS/GOARCH/GOARM and verifies the
// exit code is 0. The resulting binary is written to a temp directory and
// immediately discarded.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCrossCompilation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-compilation in short mode")
	}

	targets := []struct {
		goos, goarch, goarm string
	}{
		{"linux", "amd64", ""},
		{"linux", "arm64", ""},
		{"linux", "arm", "7"},
		{"linux", "386", ""},
		{"darwin", "amd64", ""},
		{"darwin", "arm64", ""},
	}

	tmpDir := t.TempDir()

	for _, tgt := range targets {
		name := tgt.goos + "/" + tgt.goarch
		if tgt.goarm != "" {
			name += "v" + tgt.goarm
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			outPath := filepath.Join(tmpDir, fmt.Sprintf("alcapwn-%s-%s", tgt.goos, tgt.goarch))

			cmd := exec.Command("go", "build", "-o", outPath, ".")
			cmd.Dir = filepath.Dir(outPath) // does not matter; module root is used
			// Set the module directory explicitly so `go build .` finds the module.
			cmd.Dir = "."
			cmd.Env = append(os.Environ(),
				"GOOS="+tgt.goos,
				"GOARCH="+tgt.goarch,
				"CGO_ENABLED=0",
			)
			if tgt.goarm != "" {
				cmd.Env = append(cmd.Env, "GOARM="+tgt.goarm)
			}

			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("go build failed for %s:\n%s", name, string(output))
			}

			// Verify the binary was actually produced.
			info, err := os.Stat(outPath)
			if err != nil {
				t.Fatalf("output binary not found: %v", err)
			}
			if info.Size() == 0 {
				t.Fatal("output binary is empty")
			}
		})
	}
}
