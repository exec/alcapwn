# VM Tests for alcapwn v2

This directory contains tests that run alcapwn against a real VM.

## Prerequisites

- QEMU (qemu-system-x86_64)
- cloud-image-utils (for cloud-localds)
- SSH and SSH keygen
- Go 1.21+

Install on Debian/Ubuntu:
```bash
sudo apt install qemu-system-x86 cloud-image-utils
```

## Running Tests

```bash
cd v2/tests/vm
./run_test.sh
```

## Expected Matches

The test sets up 4 privesc scenarios:

1. **SUDO_NOPASSWD_DIRECT** - cloud-init already sets up NOPASSWD:ALL
2. **SUDO_NOPASSWD_CUSTOM** - tar command with NOPASSWD
3. **SUID_GTFOBINS** - /usr/bin/find with SUID bit
4. **WRITABLE_CRON** - world-writable /etc/cron.daily/clean.sh

All 4 should be detected and reported by alcapwn.
