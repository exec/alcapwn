package main

import (
	"fmt"
	"os"
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
