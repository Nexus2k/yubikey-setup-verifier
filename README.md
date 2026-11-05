# YubiKey Setup Verifier

A command-line tool that verifies your YubiKey is correctly configured for GPG commit signing and SSH authentication.

## What it checks

1. **Git commit signing** — `commit.gpgsign = true` and `user.signingkey` are set in `~/.gitconfig`
2. **YubiKey card status** — a YubiKey is inserted and readable via `gpg --card-status`
3. **GPG key / YubiKey match** — the signing key in git config matches a key on the inserted YubiKey
4. **Touch (UIF) policy** — signing, encryption, and authentication slots all require a physical touch
5. **SSH key loaded** — a YubiKey-backed key (with a `cardno:` comment) is loaded in the SSH agent

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

Colours are only used on an interactive terminal (and never with `NO_COLOR` set), so `python3 verify.py | pbcopy` gives clean text for a pull request.

### Exporting for private signed-commits enrollment

```bash
python3 verify.py --export                       # GitHub login detected via `gh`
python3 verify.py --export <github-login> --keys-dir ../ml-signed-commits/keys
```

After all checks pass, `--export`:

- writes the public key (never the secret key) to `<keys-dir>/<github-login>.asc`
- prints a `keys/index.yaml` `people:` stanza between `----8<----` markers, with the primary fingerprint, the YubiKey's signing fingerprint, and allowed emails (`git user.email`, your GitHub noreply address if `gh` is logged in as that user, plus any `--email`)

The `verified:` block is left empty on purpose. The reviewer fills it in after the out-of-band fingerprint check; until then the whitelist validator rejects the entry.

| Option | Purpose |
|---|---|
| `--keys-dir DIR` | Where to write the `.asc` (default: current directory) |
| `--name NAME` | Name for the stanza (default: `git user.name`) |
| `--email ADDR` | Extra allowed author email, repeatable |
| `--force` | Overwrite an existing `.asc` with different content |

Export is skipped if any check fails.

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

4. Touch (UIF) policy
✓ Signing        : touch required  (on)
✓ Encryption     : touch required  (on)
✓ Authentication : touch required  (on)

5. SSH key loaded from YubiKey
✓ YubiKey SSH key loaded: cardno:000123456789

Summary
✓ All checks passed
```
