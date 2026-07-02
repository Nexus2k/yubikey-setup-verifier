# YubiKey Setup Verifier

A command-line tool that verifies your YubiKey is correctly configured for GPG commit signing and SSH authentication.

## What it checks

1. **Git commit signing** — `commit.gpgsign = true` and `user.signingkey` are set in `~/.gitconfig`
2. **YubiKey card status** — a YubiKey is inserted and readable via `gpg --card-status`
3. **GPG key / YubiKey match** — the signing key in git config matches a key on the inserted YubiKey
4. **SSH key loaded** — a YubiKey-backed key (with a `cardno:` comment) is loaded in the SSH agent
5. **Touch (UIF) policy** — signing, encryption, and authentication slots all require a physical touch

## Requirements

- Python 3.10+
- `gpg` (GnuPG)
- `ykman` (YubiKey Manager) — optional, needed for touch policy checks
- A YubiKey with OpenPGP keys provisioned

## Installation

```bash
brew install gnupg ykman   # macOS
```

## Usage

```bash
python3 verify.py
```

Exit code `0` means all checks passed. Any non-zero exit code indicates one or more failures — review the output for details and suggested fixes.

## Example output

```
=== YubiKey GPG Commit-Signing Verifier ===

1. Git commit signing
✓ commit.gpgsign = true
✓ user.signingkey = ABC1234567890DEF

2. YubiKey card status
✓ YubiKey detected via gpg --card-status
  Card key IDs  : sign=..., encrypt=..., auth=...

3. GPG key / YubiKey match
✓ Git signing key ABC1234567890DEF matches YubiKey sign slot

4. SSH key loaded from YubiKey
✓ YubiKey SSH key loaded: cardno:000123456789

5. Touch (UIF) policy
✓ Signing        : touch required  (on)
✓ Encryption     : touch required  (on)
✓ Authentication : touch required  (on)

Summary
✓ All checks passed
```
