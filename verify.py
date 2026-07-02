#!/usr/bin/env python3
"""Verify YubiKey GPG configuration against global git config."""

import re
import subprocess
import sys
from typing import Optional


RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BOLD = "\033[1m"


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
            if len(fp) >= 16:
                keys[slot] = fp[-16:]  # long key ID
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


def main() -> int:
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

    # ── 4. SSH key via YubiKey ───────────────────────────────────────────────
    # Must run BEFORE the ykman check: ykman takes exclusive card access and
    # knocks scdaemon off the card, which empties the agent's card-backed keys
    # until the next gpg --card-status.
    print(header("4. SSH key loaded from YubiKey"))
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

    # ── 5. Touch policy ──────────────────────────────────────────────────────
    print(header("5. Touch (UIF) policy"))

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

    # ── Summary ──────────────────────────────────────────────────────────────
    print(header("Summary"))
    if exit_code == 0:
        print(ok("All checks passed"))
    else:
        print(fail("One or more checks failed — review output above"))

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
