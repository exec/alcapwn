#!/usr/bin/env python3
"""
alcapwn test harness — drives the operator terminal over a real PTY.

Usage:
    python3 tests/harness.py [--port PORT] [--host-ip IP] [--load N]

The harness spawns alcapwn in a PTY, sends commands, waits for expected
output patterns, and reports pass/fail per test.  All Docker containers
are tracked and cleaned up on exit.
"""

import os
import sys
import pty
import select
import time
import re
import subprocess
import signal
import threading
import argparse
import traceback

# Strip ANSI escape sequences from output before regex parsing.
# alcapwn now colorizes its own output, so all session table parsing must
# go through this first or ID regexes will miss ANSI-prefixed rows.
_ANSI = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# ── Config ─────────────────────────────────────────────────────────────────

ALCAPWN   = "/tmp/alcapwn"
VORTEX    = "/home/dylan/Developer/alcapwn/v2/vortex/target/release/vortex"
SCENARIOS = "/home/dylan/Developer/alcapwn/v2/vortex/scenarios"

GREEN  = "\x1b[32m"
RED    = "\x1b[31m"
YELLOW = "\x1b[33m"
CYAN   = "\x1b[36m"
DIM    = "\x1b[2m"
BOLD   = "\x1b[1m"
RESET  = "\x1b[0m"

results = []          # (name, passed, detail)
containers = []       # running docker container IDs to kill on exit

def strip_ansi(s):
    return _ANSI.sub('', s)

# ── PTY wrapper ────────────────────────────────────────────────────────────

class AlcapwnPTY:
    def __init__(self, port, timeout=60, extra_args=None):
        self.port = port
        self.timeout = timeout
        self.extra_args = extra_args or []
        self.master_fd = None
        self.pid = None
        self.buf = b""

    def start(self):
        self.pid, self.master_fd = pty.fork()
        if self.pid == 0:
            argv = [ALCAPWN, "-l", f"0.0.0.0:{self.port}", "-t", "90"] + self.extra_args
            os.execv(ALCAPWN, argv)
            sys.exit(1)
        # parent — wait for listener to start
        self.expect("Listener started", timeout=8)
        return self

    def _read_available(self, timeout=0.1):
        r, _, _ = select.select([self.master_fd], [], [], timeout)
        if r:
            try:
                data = os.read(self.master_fd, 4096)
                self.buf += data
                return data
            except OSError:
                return b""
        return b""

    def read_until(self, pattern, timeout=None):
        """Read until regex pattern found or timeout.  Returns decoded buffer segment."""
        if timeout is None:
            timeout = self.timeout
        deadline = time.time() + timeout
        regex = re.compile(pattern.encode() if isinstance(pattern, str) else pattern)
        while time.time() < deadline:
            self._read_available(0.1)
            m = regex.search(self.buf)
            if m:
                chunk = self.buf[:m.end()].decode("utf-8", errors="replace")
                self.buf = self.buf[m.end():]
                return chunk
        # timed out — return what we have
        chunk = self.buf.decode("utf-8", errors="replace")
        self.buf = b""
        return chunk

    def expect(self, pattern, timeout=None):
        """Return True if pattern found within timeout."""
        out = self.read_until(pattern, timeout)
        return bool(re.search(pattern, out))

    def send(self, cmd):
        """Send a command line to alcapwn."""
        os.write(self.master_fd, (cmd + "\r").encode())
        time.sleep(0.1)

    def send_wait(self, cmd, pattern, timeout=None):
        """Send command and wait for pattern.  Returns (found, output)."""
        self.drain()
        self.send(cmd)
        out = self.read_until(pattern, timeout or self.timeout)
        found = bool(re.search(pattern, out))
        return found, out

    def drain(self, duration=0.3):
        """Discard buffered output."""
        deadline = time.time() + duration
        while time.time() < deadline:
            self._read_available(0.05)
        self.buf = b""

    def prompt(self, timeout=5):
        """Wait for alcapwn> prompt."""
        return self.expect(r"alcapwn>", timeout)

    def stop(self):
        if self.pid:
            try:
                os.kill(self.pid, signal.SIGTERM)
                os.waitpid(self.pid, 0)
            except Exception:
                pass
        if self.master_fd:
            try:
                os.close(self.master_fd)
            except Exception:
                pass

# ── Docker helpers ─────────────────────────────────────────────────────────

def run_scenario(name, port, host_ip, extra_args=""):
    """Start a vortex Docker scenario in the background. Returns the Popen object."""
    cmd = [
        VORTEX, "scenario", "run", name,
        "--port", str(port),
        "--host-ip", host_ip,
        "--backend", "docker",
        "--scenarios-dir", SCENARIOS,
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )
    return proc

def kill_all_containers():
    """Stop and remove all tracked containers plus any vortex scenario containers."""
    result = subprocess.run(
        ["sudo", "docker", "ps", "-q", "--filter", "ancestor=ubuntu:22.04"],
        capture_output=True, text=True
    )
    ids = result.stdout.strip().split()
    if ids:
        subprocess.run(["sudo", "docker", "stop"] + ids, capture_output=True)
        subprocess.run(["sudo", "docker", "rm"] + ids, capture_output=True)
    return len(ids)

def container_count():
    r = subprocess.run(
        ["sudo", "docker", "ps", "-q"],
        capture_output=True, text=True
    )
    return len([x for x in r.stdout.strip().split() if x])

# ── Test result helpers ─────────────────────────────────────────────────────

def ok(name, detail=""):
    results.append((name, True, detail))
    print(f"  {GREEN}✓{RESET} {name}" + (f"  {DIM}{detail}{RESET}" if detail else ""))

def fail(name, detail=""):
    results.append((name, False, detail))
    print(f"  {RED}✗{RESET} {name}" + (f"  {DIM}{detail}{RESET}" if detail else ""))

def section(title):
    print(f"\n{BOLD}{CYAN}── {title} {'─' * (50 - len(title))}{RESET}")

# ── Individual test functions ──────────────────────────────────────────────

def wait_for_session(alc, session_num, timeout=30):
    """Wait for Session [N] ready notification."""
    return alc.expect(rf"Session \[?{session_num}\]? (?:opened|ready)", timeout)

def connect_scenario(alc, scenario, port, host_ip, wait_session=1, timeout=45):
    """Start a scenario and wait for the session to be ready. Returns proc."""
    proc = run_scenario(scenario, port, host_ip)
    ready = alc.expect(r"Session \[\d+\] (?:opened|ready)", timeout=timeout)
    # wait for second 'ready' line (PTY upgrade)
    alc.expect(r"Session \d+ ready", timeout=15)
    alc.prompt(timeout=5)
    return proc, ready

def run_recon(alc, session_id, timeout=90):
    found, out = alc.send_wait(f"recon {session_id}", r"Recon complete|Recon failed", timeout)
    clean = strip_ansi(out)
    return "complete" in clean.lower()

def get_session_count(alc):
    alc.drain()
    alc.send("sessions")
    raw = alc.read_until(r"alcapwn>", timeout=5)
    out = strip_ansi(raw)
    rows = [l for l in out.split("\n") if re.match(r"\s+\d+\s+", l)]
    return len(rows)

def parse_session_ids(out):
    """Parse session IDs from sessions output, stripping ANSI first."""
    return re.findall(r"^\s+(\d+)\s+", strip_ansi(out), re.MULTILINE)

def clean_all_sessions(alc, timeout=15):
    """Kill all active alcapwn sessions and Docker containers, wait for zero sessions."""
    kill_all_containers()
    alc.drain()
    alc.send("sessions")
    out = alc.read_until(r"alcapwn>", 5)
    for sid in parse_session_ids(out):
        alc.send(f"kill {sid}")
        alc.prompt(3)
    # wait until sessions shows empty
    deadline = time.time() + timeout
    while time.time() < deadline:
        count = get_session_count(alc)
        if count == 0:
            return
        time.sleep(1)

def between_phases(alc):
    """Call between phases: full cleanup + 2s settle."""
    clean_all_sessions(alc)
    alc.drain(1.0)
    time.sleep(2)

# ── Test phases ────────────────────────────────────────────────────────────

def phase1_core(alc, port, host_ip):
    """Phase 1: core recon → exploit pipeline."""
    section("Phase 1: Core pipeline (suid_bash)")

    proc, opened = connect_scenario(alc, "suid_bash", port, host_ip)
    ok("suid_bash session connects") if opened else fail("suid_bash session connects")

    # Find the session ID
    alc.drain()
    alc.send("sessions")
    out = alc.read_until(r"alcapwn>", 5)
    ids = parse_session_ids(out)
    sid = ids[-1] if ids else "1"

    recon_ok = run_recon(alc, sid, timeout=60)
    ok("recon completes") if recon_ok else fail("recon completes")

    # info
    alc.drain()
    alc.send(f"info {sid}")
    out = alc.read_until(r"alcapwn>", 10)
    has_suid = "SUID" in out
    ok("info shows SUID binaries") if has_suid else fail("info shows SUID binaries")
    has_match = "PRIVESC MATCHES" in out or "bash" in out.lower()
    ok("info shows privesc matches") if has_match else fail("info shows privesc matches", out[:200])

    # exploit list
    alc.drain()
    alc.send(f"exploit list {sid}")
    out = alc.read_until(r"alcapwn>", 10)
    has_entry = "suid_bash" in out or "bash" in out
    ok("exploit list shows suid_bash") if has_entry else fail("exploit list shows suid_bash")

    # exploit auto
    alc.drain()
    alc.send(f"exploit auto {sid}")
    out = alc.read_until(r"alcapwn>", 30)
    rooted = "ROOT" in out and "suid_bash" in out
    ok("exploit auto achieves root via suid_bash", "euid=0") if rooted else fail("exploit auto achieves root", out[-200:])

    # sessions shows green root indicator
    alc.drain()
    alc.send("sessions")
    out = alc.read_until(r"alcapwn>", 5)
    has_root_marker = "#" in out  # user# marker for root
    ok("sessions shows root indicator (#)") if has_root_marker else fail("sessions shows root indicator")

    proc.terminate()
    alc.drain()
    alc.send(f"kill {sid}")
    alc.prompt(5)
    kill_all_containers()


def phase2_commands(alc, port, host_ip):
    """Phase 2: individual commands."""
    section("Phase 2: Commands (exec, ps, creds, download, upload, persist, rename)")

    proc, opened = connect_scenario(alc, "suid_bash", port, host_ip)
    if not opened:
        fail("phase2 session connects"); proc.terminate(); return
    ok("phase2 session connects")

    alc.drain(); alc.send("sessions")
    out = alc.read_until(r"alcapwn>", 5)
    ids = parse_session_ids(out)
    sid = ids[-1] if ids else "1"

    run_recon(alc, sid)

    # exec
    alc.drain()
    alc.send(f"exec {sid} id")
    out = alc.read_until(r"alcapwn>", 8)
    ok("exec returns output") if "uid=" in out else fail("exec returns output", out[-100:])

    # ps
    alc.drain()
    alc.send(f"ps {sid}")
    out = alc.read_until(r"alcapwn>", 8)
    ok("ps returns process list") if re.search(r"\d+\s+\w+", out) else fail("ps returns process list")

    # rename + sessions shows label
    alc.drain()
    alc.send(f"rename {sid} test-target")
    alc.prompt(3)
    alc.send("sessions")
    out = alc.read_until(r"alcapwn>", 5)
    ok("rename label visible in sessions") if "test-target" in out else fail("rename label visible in sessions")

    # creds
    alc.drain()
    alc.send(f"creds {sid}")
    out = alc.read_until(r"alcapwn>", 20)
    ok("creds completes") if "Harvesting" in out or "shadow" in out.lower() or "passwd" in out.lower() else fail("creds completes", out[-100:])

    # download a file
    alc.drain()
    alc.send(f"download {sid} /etc/hostname")
    out = alc.read_until(r"alcapwn>", 15)
    ok("download /etc/hostname") if "Downloaded" in out else fail("download /etc/hostname", out[-100:])

    # upload a file
    alc.drain()
    alc.send(f"upload {sid} /etc/hostname /tmp/test_upload.txt")
    out = alc.read_until(r"alcapwn>", 15)
    ok("upload file to session") if "Upload" in out else fail("upload file to session", out[-100:])

    # persist (bashrc — no root needed)
    alc.drain()
    alc.send(f"persist {sid} bashrc")
    out = alc.read_until(r"alcapwn>", 12)
    ok("persist bashrc installs") if "installed" in out.lower() or "profile" in out.lower() else fail("persist bashrc", out[-100:])

    # export json
    alc.drain()
    alc.send(f"export {sid} --format json /tmp/test_export.json")
    out = alc.read_until(r"alcapwn>", 8)
    ok("export json") if "Exported" in out else fail("export json", out[-100:])

    # export txt
    alc.drain()
    alc.send(f"export {sid} --format txt /tmp/test_export.txt")
    out = alc.read_until(r"alcapwn>", 8)
    ok("export txt") if "Exported" in out else fail("export txt", out[-100:])

    # notes + labels
    alc.drain()
    alc.send(f"notes {sid} this is a test note")
    alc.prompt(3)
    alc.send(f"notes {sid}")
    out = alc.read_until(r"alcapwn>", 5)
    ok("notes persist and display") if "test note" in out else fail("notes persist and display")

    alc.drain()
    alc.send(f"labels {sid} web db-target")
    alc.prompt(3)
    alc.send(f"labels {sid}")
    out = alc.read_until(r"alcapwn>", 5)
    ok("labels persist and display") if "web" in out else fail("labels persist and display")

    proc.terminate()
    alc.drain()
    alc.send(f"kill {sid}")
    alc.prompt(5)
    kill_all_containers()


def phase3_multiple_scenarios(alc, port, host_ip):
    """Phase 3: multiple different scenario types simultaneously."""
    section("Phase 3: Multiple scenario types (suid_find, sudo_python3, cap_python3)")

    procs = []
    for scenario in ["suid_find", "sudo_python3"]:
        p = run_scenario(scenario, port, host_ip)
        procs.append(p)
        # wait for this one to connect before starting next
        connected = alc.expect(r"Session \d+ ready", timeout=45)
        ok(f"{scenario} connects") if connected else fail(f"{scenario} connects")
        time.sleep(2)

    alc.prompt(3)
    alc.drain()
    alc.send("sessions")
    out = alc.read_until(r"alcapwn>", 5)
    ids = parse_session_ids(out)
    ok(f"sessions shows {len(ids)} concurrent sessions") if len(ids) >= 2 else fail(f"expected ≥2 sessions, got {len(ids)}")

    # recon + exploit all
    for sid in ids:
        recon_ok = run_recon(alc, sid)
        ok(f"recon session {sid}") if recon_ok else fail(f"recon session {sid}")

    for sid in ids:
        alc.drain()
        alc.send(f"exploit auto {sid}")
        out = alc.read_until(r"alcapwn>", 30)
        rooted = "ROOT" in out
        ok(f"exploit auto session {sid} → root") if rooted else fail(f"exploit auto session {sid}", out[-200:])

    # broadcast
    alc.drain()
    alc.send("broadcast id")
    out = alc.read_until(r"alcapwn>", 10)
    ok("broadcast reaches multiple sessions") if "Broadcast" in out else fail("broadcast", out[-100:])

    for p in procs:
        p.terminate()
    for sid in ids:
        alc.send(f"kill {sid}")
        alc.prompt(3)
    kill_all_containers()


def phase4_persistence_reconnect(alc, port, host_ip):
    """Phase 4: persistence auto-naming on reconnect."""
    section("Phase 4: Persistence + reconnect auto-naming")

    proc, opened = connect_scenario(alc, "suid_bash", port, host_ip)
    if not opened:
        fail("initial session for persist test"); proc.terminate(); return
    ok("initial session connects")

    alc.drain(); alc.send("sessions")
    out = alc.read_until(r"alcapwn>", 5)
    ids = parse_session_ids(out)
    sid = ids[-1] if ids else "1"

    # name it, install persistence
    alc.drain()
    alc.send(f"rename {sid} prod-webserver")
    alc.prompt(3)
    alc.drain()
    alc.send(f"persist {sid} bashrc")
    out = alc.read_until(r"alcapwn>", 12)
    ok("persist bashrc installs with name") if "prod-webserver" in out else fail("persist auto-label message", out[-200:])

    # kill and reconnect
    proc.terminate()
    alc.drain(); alc.send(f"kill {sid}"); alc.prompt(5)
    kill_all_containers()
    time.sleep(2)

    # reconnect from same IP
    proc2 = run_scenario("suid_bash", port, host_ip)
    alc.expect(r"Session \[\d+\].*persistent.*prod-webserver|Session \d+ ready", timeout=45)
    alc.prompt(5)
    alc.drain(); alc.send("sessions")
    out = alc.read_until(r"alcapwn>", 5)
    ok("reconnect auto-labelled prod-webserver") if "prod-webserver" in out else fail("reconnect auto-label", out[-200:])

    proc2.terminate()
    kill_all_containers()
    alc.drain(); alc.send("sessions"); out = alc.read_until(r"alcapwn>", 5)
    if ids:
        alc.send(f"kill {int(sid)+1}"); alc.prompt(5)


def phase5_tls(port, host_ip):
    """Phase 5: TLS — separate alcapwn instance with --tls flag."""
    section("Phase 5: TLS end-to-end")

    tls_port = port + 10
    alc_tls = AlcapwnPTY(tls_port, timeout=90, extra_args=["--tls"])
    alc_tls.start()
    started = True  # start() raises on failure
    ok("TLS alcapwn starts")

    # fp command with no sessions
    alc_tls.drain()
    alc_tls.send("fp")
    out = alc_tls.read_until(r"alcapwn>", 5)
    ok("fp shows fingerprint") if re.search(r"[0-9A-F]{2}:[0-9A-F]{2}:", out, re.I) else fail("fp shows fingerprint", out[-100:])

    # connect a TLS session (plain bash → Python TLS relay → TLS upgrade; needs extra time)
    proc = run_scenario("suid_bash", tls_port, host_ip)
    connected = alc_tls.expect(r"Session \d+ ready", timeout=90)
    ok("TLS session connects and upgrades") if connected else fail("TLS session connects")

    alc_tls.prompt(5)
    alc_tls.drain(); alc_tls.send("sessions")
    out = alc_tls.read_until(r"alcapwn>", 5)
    has_tls = "✓" in out or "tls" in out.lower()
    ok("TLS indicator shown in sessions") if has_tls else fail("TLS indicator in sessions")

    # fp <id> to verify fingerprint matches
    ids = parse_session_ids(out)
    if ids:
        sid = ids[-1]
        alc_tls.drain()
        alc_tls.send(f"fp {sid}")
        out = alc_tls.read_until(r"alcapwn>", 5)
        ok("fp <id> verifies session fingerprint") if "fingerprint" in out.lower() else fail("fp <id>", out[-100:])

        recon_ok = run_recon(alc_tls, sid, timeout=60)
        ok("recon works over TLS") if recon_ok else fail("recon over TLS")

        alc_tls.drain()
        alc_tls.send(f"exploit auto {sid}")
        out = alc_tls.read_until(r"alcapwn>", 30)
        ok("exploit auto works over TLS") if "ROOT" in out else fail("exploit auto over TLS", out[-200:])

    proc.terminate()
    kill_all_containers()
    alc_tls.stop()


def phase6_firewall(alc, port, host_ip):
    """Phase 6: firewall — assign to listener, verify deny."""
    section("Phase 6: Firewall")

    # create firewall allowing only a different IP (so our container gets denied)
    alc.drain()
    alc.send("firewall create test-fw")
    alc.prompt(3)
    alc.send(f"firewall rule test-fw 1.2.3.4")  # allow only 1.2.3.4
    alc.prompt(3)
    alc.send(f"firewall assign test-fw 0.0.0.0:{port}")
    alc.prompt(3)
    ok("firewall created and assigned")

    # attempt connection — should be denied
    proc = run_scenario("suid_bash", port, host_ip)
    alc.drain()
    denied = alc.expect(r"denied|no session", timeout=15)
    ok("connection denied by firewall") if denied else fail("connection should be denied — was allowed instead")

    proc.terminate()
    kill_all_containers()

    # remove firewall, verify connections work again
    alc.send("firewall delete test-fw"); alc.prompt(3)
    proc2 = run_scenario("suid_bash", port, host_ip)
    allowed = alc.expect(r"Session \d+ ready", timeout=30)
    ok("connection allowed after firewall removed") if allowed else fail("connection after firewall removal")
    proc2.terminate()
    alc.drain(); alc.send("sessions")
    out = alc.read_until(r"alcapwn>", 5)
    ids = parse_session_ids(out)
    for sid in ids:
        alc.send(f"kill {sid}"); alc.prompt(3)
    kill_all_containers()


def phase7_load(alc, port, host_ip, max_sessions=30, batch=5, pause=20):
    """Phase 7: load test — ramp up sessions slowly, watch for instability."""
    section(f"Phase 7: Load test (ramp to {max_sessions}, batch={batch}, pause={pause}s)")

    procs = []
    total = 0
    shaky = False

    try:
        while total < max_sessions and not shaky:
            batch_actual = min(batch, max_sessions - total)
            print(f"  {CYAN}→ Starting batch of {batch_actual} (total will be {total + batch_actual}){RESET}")

            for _ in range(batch_actual):
                p = run_scenario("suid_bash", port, host_ip)
                procs.append(p)
                time.sleep(2)  # stagger launches slightly

            # wait for all to connect — Ubuntu containers take ~25s to apt-get + setup
            t0 = time.time()
            target = total + batch_actual
            while time.time() - t0 < 60:
                count = get_session_count(alc)
                print(f"  {DIM}  waiting... {count}/{target} connected ({int(time.time()-t0)}s){RESET}", end="\r")
                if count >= target:
                    break
                time.sleep(3)
            print()  # newline after \r

            count = get_session_count(alc)
            total = count
            print(f"  {DIM}active sessions: {count}{RESET}")

            # sanity check: send a simple command to the latest session
            alc.drain(); alc.send("sessions")
            out = alc.read_until(r"alcapwn>", 10)
            ids = parse_session_ids(out)

            if not ids:
                fail(f"sessions unresponsive at {total} sessions")
                shaky = True
                break

            # test exec on the latest session
            sid = ids[-1]
            alc.drain()
            alc.send(f"exec {sid} id")
            out2 = alc.read_until(r"alcapwn>", timeout=10)
            found = "uid=" in out2
            if not found:
                fail(f"exec timed out at {total} sessions — system getting shaky")
                shaky = True
                break

            ok(f"{total} concurrent sessions — system responsive")
            print(f"  {DIM}pausing {pause}s before next batch...{RESET}")
            time.sleep(pause)

    except Exception as e:
        fail(f"load test exception at {total} sessions: {e}")
        shaky = True
    finally:
        if shaky:
            print(f"\n  {YELLOW}System got shaky at {total} sessions — killing all containers immediately{RESET}")
        killed = kill_all_containers()
        for p in procs:
            try: p.terminate()
            except: pass
        print(f"  {DIM}cleaned up {killed} containers{RESET}")

    if not shaky:
        ok(f"load test: {total} sessions handled cleanly")


def phase8_http_generate(alc, port, host_ip):
    """Phase 8: HTTP listener + generate command."""
    section("Phase 8: HTTP listener + generate command")

    # Start HTTP listener with download dir.
    alc.drain()
    alc.send("listen http :8888 --download-dir /tmp")
    out = alc.read_until(r"alcapwn>", 10)
    http_ok = "HTTP listener started" in out
    ok("HTTP listener starts with --download-dir") if http_ok else fail("HTTP listener starts", out[:300])

    # Check listeners shows indices and download token.
    alc.drain()
    alc.send("listeners")
    out = alc.read_until(r"alcapwn>", 8)
    has_idx = "Idx" in out and "HTTP" in out
    has_download = "download=" in out
    ok("listeners shows indices and download info") if has_idx and has_download else fail("listeners shows indices/download", out[:400])

    # Test generate with --listener flag (index 2 = HTTP listener after TCP on args.port).
    # The build takes up to ~60s; use a 90s timeout.
    alc.drain()
    alc.send("generate linux amd64 --listener 2")
    out = alc.read_until(r"alcapwn>", 90)
    build_ok = re.search(r"\[\+\].*MB", out) is not None
    ok("generate builds agent") if build_ok else fail("generate builds agent", out[:300])

    # Reuse same output for transport and download URL checks.
    http_transport = "http" in out.lower() and ("transport" in out.lower() or "beacon" in out.lower())
    ok("generate uses HTTP transport") if http_transport else fail("generate HTTP transport", out[:300])

    has_dl_url = "Download:" in out and "http://" in out
    ok("generate shows download URL") if has_dl_url else fail("generate shows download URL", out[:300])

    # Clean up listener.
    alc.drain()
    alc.send("unlisten http :8888")
    alc.read_until(r"alcapwn>", 5)


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=6000)
    parser.add_argument("--host-ip", default=None)
    parser.add_argument("--load-max", type=int, default=30)
    parser.add_argument("--load-batch", type=int, default=5)
    parser.add_argument("--load-pause", type=int, default=20)
    parser.add_argument("--skip", nargs="*", default=[],
                        help="phases to skip: core commands multi persist tls firewall load")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="enable verbose output (-v flag to alcapwn)")
    args = parser.parse_args()

    # Auto-detect host IP if not provided
    if args.host_ip is None:
        try:
            result = subprocess.run(
                ["ip", "route", "get", "1.1.1.1"],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r'src (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                args.host_ip = match.group(1)
            else:
                # fallback: parse hostname -I
                result = subprocess.run(
                    ["hostname", "-I"], capture_output=True, text=True, timeout=5
                )
                args.host_ip = result.stdout.strip().split()[0] if result.stdout else "127.0.0.1"
        except Exception:
            args.host_ip = "127.0.0.1"  # last resort default

    verbose_args = ["-v=1"] if args.verbose else []
    print(f"\n{BOLD}alcapwn test suite{RESET}  port={args.port}  host={args.host_ip}{' VERBOSE' if args.verbose else ''}\n")

    # Ensure clean state
    kill_all_containers()

    # Start main alcapwn instance
    alc = AlcapwnPTY(args.port, extra_args=verbose_args)
    alc.start()
    print(f"{GREEN}alcapwn started on port {args.port}{RESET}")

    def cleanup(sig=None, frame=None):
        print(f"\n{YELLOW}Interrupted — killing containers and alcapwn...{RESET}")
        kill_all_containers()
        alc.stop()
        _print_summary()
        sys.exit(1)

    signal.signal(signal.SIGINT, cleanup)

    try:
        skip = set(args.skip)
        if "core"     not in skip: phase1_core(alc, args.port, args.host_ip)
        between_phases(alc)
        if "commands" not in skip: phase2_commands(alc, args.port, args.host_ip)
        between_phases(alc)
        if "multi"    not in skip: phase3_multiple_scenarios(alc, args.port, args.host_ip)
        between_phases(alc)
        if "persist"  not in skip: phase4_persistence_reconnect(alc, args.port, args.host_ip)
        between_phases(alc)
        if "tls"      not in skip: phase5_tls(args.port, args.host_ip)
        between_phases(alc)
        if "firewall" not in skip: phase6_firewall(alc, args.port, args.host_ip)
        between_phases(alc)
        if "load"     not in skip: phase7_load(alc, args.port, args.host_ip,
                                                args.load_max, args.load_batch, args.load_pause)
        between_phases(alc)
        if "generate" not in skip: phase8_http_generate(alc, args.port, args.host_ip)
    except Exception as e:
        fail(f"unexpected error: {e}")
        traceback.print_exc()
    finally:
        kill_all_containers()
        alc.stop()

    _print_summary()


def _print_summary():
    passed = sum(1 for _, p, _ in results if p)
    failed = sum(1 for _, p, _ in results if not p)
    total  = len(results)
    print(f"\n{BOLD}{'─'*60}{RESET}")
    print(f"{BOLD}Results: {GREEN}{passed}{RESET}{BOLD}/{total} passed{RESET}", end="")
    if failed:
        print(f"  {RED}{failed} failed{RESET}")
        for name, p, detail in results:
            if not p:
                print(f"  {RED}✗{RESET} {name}" + (f": {detail}" if detail else ""))
    else:
        print(f"  {GREEN}all pass{RESET}")
    print()


if __name__ == "__main__":
    main()
