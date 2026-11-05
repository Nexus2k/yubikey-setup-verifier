#!/usr/bin/env python3
"""Verify YubiKey GPG configuration against global git config.

With --export, also writes <github-login>.asc and prints the keys/index.yaml
`people:` stanza for enrollment in ml-signed-commits.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import date
from pathlib import Path
from typing import Optional


# Colours only on an interactive terminal, so piped / redirected output is
# clean to paste into a pull request. NO_COLOR (https://no-color.org) wins.
_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
RESET = "\033[0m" if _COLOR else ""
RED = "\033[31m" if _COLOR else ""
GREEN = "\033[32m" if _COLOR else ""
YELLOW = "\033[33m" if _COLOR else ""
BOLD = "\033[1m" if _COLOR else ""

FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}$")
GITHUB_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")


def ok(msg: str) -> str:
    return f"{GREEN}✓{RESET} {msg}"


def fail(msg: str) -> str:
    return f"{RED}✗{RESET} {msg}"


def warn(msg: str) -> str:
    return f"{YELLOW}!{RESET} {msg}"


def header(msg: str) -> str:
    return f"\n{BOLD}{msg}{RESET}"


def run(cmd: list) -> tuple:
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def get_git_config(key: str) -> Optional[str]:
    code, out, _ = run(["git", "config", "--global", key])
    return out.strip() if code == 0 and out.strip() else None


def check_commit_signing() -> tuple:
    """Return (signing_enabled, key_id)."""
    sign = get_git_config("commit.gpgsign")
    key_id = get_git_config("user.signingkey")
    enabled = sign is not None and sign.lower() in ("true", "1", "yes")
    return enabled, key_id


def get_card_status() -> tuple:
    code, out, err = run(["gpg", "--card-status"])
    return code, out + err


def parse_card_key_ids(card_output: str) -> dict[str, str]:
    """
    Extract the fingerprints from card-status output and return the last 16 hex
    chars (long key ID) for each slot: sign, encrypt, auth.
    """
    return {slot: fp[-16:] for slot, fp in parse_card_fingerprints(card_output).items()}


def parse_card_fingerprints(card_output: str) -> dict[str, str]:
    """Return the full 40-hex fingerprint for each card slot: sign, encrypt, auth."""
    keys: dict[str, str] = {}
    # Card-status prints fingerprints like:
    #   Signature key ....: AABB CCDD ...
    #   Encryption key....: ...
    #   Authentication key: ...
    # and also a "General key info" block with subkey fingerprints.
    # We parse the three dedicated fingerprint lines.
    patterns = {
        "sign": r"Signature key\s*\.+:\s*([0-9A-F ]{40,})",
        "encrypt": r"Encryption key\s*\.+:\s*([0-9A-F ]{40,})",
        "auth": r"Authentication key\s*:\s*([0-9A-F ]{40,})",
    }
    for slot, pattern in patterns.items():
        m = re.search(pattern, card_output, re.IGNORECASE)
        if m:
            fp = m.group(1).replace(" ", "").upper()
            if FINGERPRINT_RE.fullmatch(fp):
                keys[slot] = fp
    return keys


def normalize_key_id(key_id: str) -> str:
    """Strip leading 0x and uppercase."""
    return key_id.lstrip("0x").lstrip("0X").upper()


def key_matches_card(git_key_id: str, card_key_ids: dict) -> tuple:
    """Return (matched, slot_name)."""
    normalized = normalize_key_id(git_key_id)
    for slot, card_id in card_key_ids.items():
        # card_id is 16 chars; git key may be 8 (short) or 16 (long) or 40 (fp)
        if card_id.endswith(normalized) or normalized.endswith(card_id):
            return True, slot
    return False, ""


def parse_touch_policy(card_output: str) -> dict[str, str]:
    """
    Parse touch policy from ykman openpgp info output.
    Handles both formats:
      - New: section header + "Touch policy: On/Off/Fixed/Cached"
      - Old: "UIF for Signature: on/off"
    Returns dict with keys 'sign', 'encrypt', 'auth'.
    """
    touch: dict[str, str] = {}

    # New ykman format: each key has a section followed by "Touch policy: X"
    section_patterns = {
        "sig": r"Signature key\s*:.*?Touch policy:\s*(\S+)",
        "enc": r"(?:Decryption|Encryption) key\s*:.*?Touch policy:\s*(\S+)",
        "aut": r"Authentication key\s*:.*?Touch policy:\s*(\S+)",
    }
    for slot, pattern in section_patterns.items():
        m = re.search(pattern, card_output, re.IGNORECASE | re.DOTALL)
        if m:
            touch[slot] = m.group(1).lower()

    if touch:
        return touch

    # Fallback: old ykman format "UIF for Signature: off"
    uif_patterns = {
        "sig": r"UIF for Signature\s*:\s*(\S+)",
        "enc": r"UIF for (?:Decryption|Encryption)\s*:\s*(\S+)",
        "aut": r"UIF for Authentication\s*:\s*(\S+)",
    }
    for slot, pattern in uif_patterns.items():
        m = re.search(pattern, card_output, re.IGNORECASE)
        if m:
            touch[slot] = m.group(1).lower()

    return touch


def get_ykman_openpgp_info() -> tuple:
    """Try ykman openpgp info for touch policy. Returns (available, output)."""
    code, out, err = run(["ykman", "openpgp", "info"])
    if code == 0:
        return True, out
    # Try older ykman syntax
    code2, out2, err2 = run(["ykman", "openpgp", "touch"])
    if code2 == 0:
        return True, out2
    return False, err + err2


def touch_enforced(policy: str) -> bool:
    return policy.lower() in ("on", "fixed", "cached", "cached-fixed")


def check_ssh_yubikey() -> tuple:
    """
    Return (status, keys) where status is one of:
      'no_agent'  — ssh-agent is not reachable (SSH_AUTH_SOCK not set / agent dead)
      'no_yubikey' — agent is running but no key with a cardno: comment is loaded
      'found'     — at least one YubiKey-backed key is loaded
    keys is a list of matching comment strings (only populated for 'found').
    """
    code, out, err = run(["ssh-add", "-l"])
    if code == 2:
        # exit 2 means the agent is not running / not reachable
        return "no_agent", []
    matching = []
    for line in out.splitlines():
        # Each line: <bits> <fingerprint> <comment> (<type>)
        # We look for 'cardno:' anywhere in the comment field.
        if "cardno:" in line.lower():
            # Extract the comment (3rd field onward, before the trailing type)
            parts = line.split()
            if len(parts) >= 3:
                comment = " ".join(parts[2:-1]) if len(parts) > 3 else parts[2]
                matching.append(comment)
    return ("found" if matching else "no_yubikey"), matching


# ── Export for ml-signed-commits ─────────────────────────────────────────────


def lookup_primary_key(signing_fpr: str) -> Optional[dict]:
    """
    Find the primary key that owns `signing_fpr` (a subkey or the primary itself).
    Returns {primary, validity, uids, signers} or None.
    """
    code, out, _ = run(["gpg", "--with-colons", "--fixed-list-mode",
                        "--with-subkey-fingerprint", "--list-keys", signing_fpr])
    if code != 0:
        return None
    current: Optional[dict] = None
    pending: Optional[tuple] = None   # (record type, validity, capabilities)
    found: Optional[dict] = None
    for line in out.splitlines():
        f = line.split(":")
        rec = f[0]
        if rec == "pub":
            if current and found is None and signing_fpr in current["all"]:
                found = current
            current = {"primary": None, "validity": f[1], "uids": [], "signers": [], "all": set()}
            pending = ("pub", f[1], f[11] if len(f) > 11 else "")
        elif rec == "sub":
            pending = ("sub", f[1], f[11] if len(f) > 11 else "")
        elif rec == "fpr" and current is not None and pending is not None:
            fpr = f[9].upper()
            kind, validity, caps = pending
            if kind == "pub":
                current["primary"] = fpr
            current["all"].add(fpr)
            if "s" in caps and validity not in ("e", "r"):
                current["signers"].append(fpr)
            pending = None
        elif rec == "uid" and current is not None and f[1] not in ("r", "e"):
            current["uids"].append(f[9])
    if current and found is None and signing_fpr in current["all"]:
        found = current
    return found


def uid_name(uid: str) -> str:
    """'Jane Doe (comment) <jane@x>' -> 'Jane Doe'"""
    return re.sub(r"\s*(\(.*?\))?\s*<[^>]*>\s*$", "", uid).strip()


def github_identity() -> tuple:
    """Return (login, noreply_email) from the gh CLI, or (None, None)."""
    try:
        code, out, _ = run(["gh", "api", "user", "--jq", '"\\(.login) \\(.id)"'])
    except FileNotFoundError:
        return None, None
    parts = out.split()
    if code != 0 or len(parts) != 2:
        return None, None
    login, uid = parts
    return login, f"{uid}+{login}@users.noreply.github.com"


def yaml_scalar(value: str) -> str:
    """Emit a YAML scalar, double-quoting anything that is not obviously plain."""
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 .@+_\-]*", value) and not value.endswith(" "):
        return value
    return json.dumps(value, ensure_ascii=False)


def people_stanza(login: str, name: str, key_path: str, primary: str,
                  signers: list, emails: list) -> str:
    lines = [
        f"  - github: {yaml_scalar(login)}",
        f"    name: {yaml_scalar(name)}",
        f"    key: {key_path}",
        "    fingerprints:",
        f"      - {primary}",
        "    signing_fingerprints:",
        *[f"      - {s}" for s in signers],
        "    emails:",
        *[f"      - {yaml_scalar(e)}" for e in emails],
        "    status: active",
        "    verified:",
        "      # Filled in by the reviewer after the out-of-band fingerprint check.",
        "      # Left empty on purpose: validate_whitelist.py rejects this until then.",
        "      by: \"\"",
        f"      date: \"\"  # e.g. {date.today().isoformat()}",
        "      method: \"\"  # e.g. fingerprint read back over a video call",
    ]
    return "\n".join(lines)


def export_enrollment(args, card_fprs: dict) -> int:
    """Write <login>.asc and print the index.yaml stanza. Returns an exit code."""
    print(header("Export for ml-signed-commits"))

    signing_fpr = card_fprs.get("sign")
    if not signing_fpr:
        print(fail("No full signing-slot fingerprint found in gpg --card-status"))
        return 1

    key = lookup_primary_key(signing_fpr)
    if key is None or not key["primary"]:
        print(fail(f"Public key for card signing key {signing_fpr} is not in your keyring"))
        print("  Import it (e.g. gpg --card-edit → fetch, or gpg --import <pubkey>) and re-run.")
        return 1
    primary = key["primary"]
    if key["validity"] in ("e", "r"):
        state = "expired" if key["validity"] == "e" else "revoked"
        print(fail(f"Primary key {primary} is {state} — CI will reject it. Renew or rotate first."))
        return 1
    if signing_fpr not in key["signers"]:
        print(fail(f"Card signing key {signing_fpr} is expired, revoked, or not signing-capable"))
        return 1

    gh_login, gh_noreply = github_identity()
    login = args.export if args.export != "auto" else gh_login
    if not login:
        print(fail("Could not determine your GitHub login. Pass it: --export <github-login>"))
        return 1
    if not GITHUB_LOGIN_RE.fullmatch(login):
        print(fail(f"'{login}' is not a valid GitHub login"))
        return 1

    name = (args.name or get_git_config("user.name")
            or next((uid_name(u) for u in key["uids"] if uid_name(u)), ""))
    if not name:
        print(fail("Could not determine your name. Pass it: --name 'Your Name'"))
        return 1

    emails: list = []
    candidates = [get_git_config("user.email"), *(args.email or [])]
    if gh_noreply and gh_login and gh_login.lower() == login.lower():
        candidates.append(gh_noreply)
    for e in candidates:
        if e and e.strip().lower() not in emails:
            emails.append(e.strip().lower())
    if not emails:
        print(fail("No author email found. Set git user.email or pass --email"))
        return 1

    # Public export only. Never the secret key.
    code, armored, err = run(["gpg", "--armor", "--export-options", "export-clean",
                              "--export", primary])
    if code != 0 or "BEGIN PGP PUBLIC KEY BLOCK" not in armored:
        print(fail(f"gpg --export {primary} failed: {err.strip()}"))
        return 1
    if "PRIVATE KEY BLOCK" in armored:
        print(fail("Export unexpectedly contains private key material — aborting"))
        return 1

    out_dir = Path(args.keys_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    asc_path = out_dir / f"{login}.asc"
    if asc_path.exists() and asc_path.read_text() != armored and not args.force:
        print(fail(f"{asc_path} already exists with different content (use --force, "
                   "or a distinct name for rotation)"))
        return 1
    asc_path.write_text(armored)
    print(ok(f"Wrote public key: {asc_path}"))

    print(f"  Primary fingerprint : {primary}")
    print(f"  Signing fingerprint : {signing_fpr}")
    if signing_fpr == primary:
        print("  (the primary key itself is the signing key)")
    print(f"  Emails              : {', '.join(emails)}")
    if not (gh_noreply and gh_login and gh_login.lower() == login.lower()):
        print(warn("GitHub noreply address not added (gh CLI unavailable or different login)."))
        print("  Add it with --email if you commit via that address:")
        print("    gh api user --jq '\"\\(.id)+\\(.login)@users.noreply.github.com\"'")

    stanza = people_stanza(login, name, f"keys/{login}.asc", primary, [signing_fpr], emails)
    print("\nAppend to keys/index.yaml under `people:`")
    print("----8<----")
    print(stanza)
    print("----8<----")
    return 0


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Verify YubiKey GPG commit-signing setup.")
    p.add_argument("--export", nargs="?", const="auto", metavar="GITHUB_LOGIN",
                   help="after all checks pass, write <GITHUB_LOGIN>.asc and print the "
                        "ml-signed-commits keys/index.yaml stanza (login auto-detected via gh "
                        "if omitted)")
    p.add_argument("--keys-dir", default=".", metavar="DIR",
                   help="where to write the .asc file (default: current directory; "
                        "point at ml-signed-commits/keys to drop it in place)")
    p.add_argument("--name", help="name for the stanza (default: git user.name)")
    p.add_argument("--email", action="append", metavar="ADDR",
                   help="extra allowed author email (repeatable); git user.email is always included")
    p.add_argument("--force", action="store_true", help="overwrite an existing, different .asc")
    return p.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    args = parse_args(argv)
    exit_code = 0

    print(header("=== YubiKey GPG Commit-Signing Verifier ==="))

    # ── 1. Commit signing ────────────────────────────────────────────────────
    print(header("1. Git commit signing"))
    signing_on, git_key_id = check_commit_signing()

    if signing_on:
        print(ok("commit.gpgsign = true"))
    else:
        print(fail("commit.gpgsign is not enabled (set to 'true' in ~/.gitconfig)"))
        exit_code = 1

    if git_key_id:
        print(ok(f"user.signingkey = {git_key_id}"))
    else:
        print(fail("user.signingkey is not set in ~/.gitconfig"))
        exit_code = 1

    if not signing_on or not git_key_id:
        print("\nCannot continue without signing key configured.")
        return exit_code

    # ── 2. Card status ───────────────────────────────────────────────────────
    print(header("2. YubiKey card status"))
    card_code, card_output = get_card_status()

    if card_code != 0:
        print(fail("Could not read card status — is a YubiKey inserted?"))
        print(f"  {card_output.strip()}")
        return 1

    print(ok("YubiKey detected via gpg --card-status"))

    card_fprs = parse_card_fingerprints(card_output)
    card_key_ids = parse_card_key_ids(card_output)
    if not card_key_ids:
        print(warn("Could not parse key fingerprints from card-status output"))
    else:
        slots = ", ".join(f"{s}={k}" for s, k in card_key_ids.items())
        print(f"  Card key IDs  : {slots}")

    # ── 3. Key match ─────────────────────────────────────────────────────────
    print(header("3. GPG key / YubiKey match"))
    matched, matched_slot = key_matches_card(git_key_id, card_key_ids)

    if matched:
        print(ok(f"Git signing key {git_key_id} matches YubiKey {matched_slot} slot"))
    else:
        print(fail(f"Git signing key {git_key_id} does NOT match any key on the YubiKey"))
        print(f"  Card keys: {card_key_ids or 'none found'}")
        exit_code = 1

    # ── 4. Touch policy ──────────────────────────────────────────────────────
    print(header("4. Touch (UIF) policy"))

    ykman_ok, ykman_out = get_ykman_openpgp_info()

    if not ykman_ok:
        print(warn("ykman not available or failed — cannot check touch policy"))
        print(f"  Install via: brew install ykman")
        print(f"  {ykman_out.strip()}")
    else:
        touch = parse_touch_policy(ykman_out)
        if not touch:
            print(warn("Could not parse touch/UIF policy from ykman output"))
            print(f"  Raw output:\n{ykman_out.strip()}")
            exit_code = 1
        else:
            slots_checked = {"sig": "Signing", "enc": "Encryption", "aut": "Authentication"}
            for slot, label in slots_checked.items():
                policy = touch.get(slot)
                if policy is None:
                    print(warn(f"{label:15s}: policy not found in ykman output"))
                elif touch_enforced(policy):
                    print(ok(f"{label:15s}: touch required  ({policy})"))
                else:
                    print(fail(f"{label:15s}: touch NOT required ({policy})"))
                    print(f"    Fix: ykman openpgp keys set-touch {slot} on")
                    exit_code = 1

    # ── 5. SSH key via YubiKey ───────────────────────────────────────────────
    print(header("5. SSH key loaded from YubiKey"))
    ssh_status, ssh_keys = check_ssh_yubikey()

    if ssh_status == "found":
        for k in ssh_keys:
            print(ok(f"YubiKey SSH key loaded: {k}"))
    elif ssh_status == "no_agent":
        print(fail("SSH agent is not running or not reachable"))
        print("  To use gpg-agent as your SSH agent:")
        print("    1. Add to ~/.gnupg/gpg-agent.conf:  enable-ssh-support")
        print("    2. Restart the agent:               gpgconf --kill gpg-agent && gpgconf --launch gpg-agent")
        print("    3. Point SSH at the gpg-agent socket (add to ~/.zshrc / ~/.bashrc):")
        print("         export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)")
        print("    4. Re-open your terminal (or source the file), then re-run this script.")
        exit_code = 1
    else:
        print(warn("No YubiKey-backed SSH key found in ssh-agent (no cardno: comment)"))
        print("  Ensure the YubiKey auth subkey is known to gpg-agent:")
        print("    gpg --card-status   # imports the auth subkey stub if not yet present")
        exit_code = 1

    # ── Summary ──────────────────────────────────────────────────────────────
    print(header("Summary"))
    if exit_code == 0:
        print(ok("All checks passed"))
    else:
        print(fail("One or more checks failed — review output above"))

    # ── Optional export ──────────────────────────────────────────────────────
    if args.export:
        if exit_code != 0:
            print(header("Export for ml-signed-commits"))
            print(fail("Skipped: all checks must pass before enrolling (see docs/ENROLLMENT.md)"))
        else:
            exit_code = export_enrollment(args, card_fprs)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
