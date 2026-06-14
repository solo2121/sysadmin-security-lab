#!/usr/bin/env python3
"""
Hashcat Interactive CLI
=======================

Author: Miguel Carlo
Version: 1.0.0
License: MIT

Description:
A professional, menu‑driven interface for Hashcat that simplifies building
and executing password‑recovery commands while preserving flexibility
for advanced use cases.

Key Features:
- Guided workflow for building Hashcat commands
- Supports common hash types and attack modes
- Optional performance and output flags
- Command preview before execution
- Input validation for files and parameters

Requirements:
- Python 3.8+
- Hashcat installed and available in PATH

Legal Notice:
This tool is intended ONLY for authorized security testing,
password recovery, and educational use. Unauthorized use
against systems without permission may be illegal.
"""

import os
import subprocess
import sys
import shutil
from typing import Optional, Dict


APP_NAME = "Hashcat Interactive CLI"
VERSION = "1.0.0"


# ------------------------------------------------------------
# Utility Functions
# ------------------------------------------------------------
def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def print_header() -> None:
    print(f"{APP_NAME}  |  Version {VERSION}")
    print("-" * 50)


def validate_file(path: str, description: str) -> str:
    while True:
        if os.path.isfile(path):
            return path
        print(f"[!] {description} not found: {path}")
        path = input(f"Enter a valid {description}: ").strip()


# ------------------------------------------------------------
# User Input Functions
# ------------------------------------------------------------
def get_hash_file() -> str:
    path = input("Path to hash file: ").strip()
    return validate_file(path, "hash file")


def get_wordlist() -> str:
    path = input("Path to wordlist: ").strip()
    return validate_file(path, "wordlist")


def get_hash_type() -> str:
    hashes: Dict[str, Dict[str, str]] = {
        "1": {"name": "MD5", "code": "0"},
        "2": {"name": "SHA1", "code": "100"},
        "3": {"name": "SHA256", "code": "1400"},
        "4": {"name": "SHA512", "code": "1700"},
        "5": {"name": "NTLM", "code": "1000"},
        "6": {"name": "LM", "code": "3000"},
        "7": {"name": "WordPress", "code": "400"},
        "8": {"name": "Joomla", "code": "11"},
        "9": {"name": "Unix Crypt", "code": "500"},
        "10": {"name": "Custom", "code": ""},
    }

    print("\nSelect hash type:")
    for k, v in hashes.items():
        print(f"{k}. {v['name']}")

    while True:
        choice = input("Choice: ").strip()
        if choice in hashes:
            if choice == "10":
                return input("Enter custom hashcat code: ").strip()
            return hashes[choice]["code"]
        print("Invalid selection.")


def get_attack_type() -> Dict[str, str]:
    attacks = {
        "1": {"name": "Dictionary", "mode": "0"},
        "2": {"name": "Combinator", "mode": "1"},
        "3": {"name": "Mask", "mode": "3"},
        "4": {"name": "Hybrid Dict + Mask", "mode": "6"},
        "5": {"name": "Hybrid Mask + Dict", "mode": "7"},
        "6": {"name": "Rule‑based", "mode": "0_rules"},
        "7": {"name": "Toggle Case", "mode": "2"},
        "8": {"name": "Brute Force", "mode": "3"},
    }

    print("\nSelect attack mode:")
    for k, v in attacks.items():
        print(f"{k}. {v['name']}")

    while True:
        choice = input("Choice: ").strip()
        if choice in attacks:
            return attacks[choice]
        print("Invalid selection.")


# ------------------------------------------------------------
# Command Builder
# ------------------------------------------------------------
def build_command(
    hash_file: str,
    hash_type: str,
    attack: Dict[str, str],
    wordlist: Optional[str] = None,
    mask: Optional[str] = None,
    rules: Optional[str] = None,
) -> list:

    cmd = ["hashcat", "-m", hash_type]

    mode = attack["mode"]

    if mode == "0":
        cmd += ["-a", "0", hash_file, wordlist]

    elif mode == "1":
        cmd += ["-a", "1", hash_file, wordlist, wordlist]

    elif mode == "3":
        if not mask:
            mask = input("Mask pattern (e.g. ?d?d?d?d): ").strip()
        cmd += ["-a", "3", hash_file, mask]

    elif mode == "6":
        mask = mask or "?a?a?a?a"
        cmd += ["-a", "6", hash_file, wordlist, mask]

    elif mode == "7":
        mask = mask or "?a?a?a?a"
        cmd += ["-a", "7", hash_file, mask, wordlist]

    elif mode == "0_rules":
        rules = rules or input("Rule file (e.g. best64.rule): ").strip()
        cmd += ["-a", "0", "-r", rules, hash_file, wordlist]

    elif mode == "2":
        cmd += ["-a", "2", hash_file, wordlist]

    # Optional flags
    if input("Enable optimized kernel (-O)? [y/N]: ").lower() == "y":
        cmd.append("-O")

    if input("Force execution (--force)? [y/N]: ").lower() == "y":
        cmd.append("--force")

    if input("Show cracked passwords (--show)? [y/N]: ").lower() == "y":
        cmd.append("--show")

    return cmd


# ------------------------------------------------------------
# Main Application Flow
# ------------------------------------------------------------
def main() -> None:
    clear_screen()
    print_header()

    if not shutil.which("hashcat"):
        print("[!] Hashcat not found in PATH.")
        sys.exit(1)

    hash_file = get_hash_file()
    hash_type = get_hash_type()
    attack = get_attack_type()

    wordlist = None
    if attack["mode"] in ["0", "1", "6", "7", "0_rules", "2"]:
        wordlist = get_wordlist()

    mask = None
    if attack["mode"] in ["3", "6", "7"]:
        if input("Specify mask? [y/N]: ").lower() == "y":
            mask = input("Mask: ").strip()

    rules = None
    if attack["mode"] == "0_rules":
        rules = input("Rule file: ").strip()

    cmd = build_command(hash_file, hash_type, attack, wordlist, mask, rules)

    print("\nGenerated command:")
    print(" ".join(cmd))

    if input("\nExecute command? [y/N]: ").lower() == "y":
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[!] Hashcat error: {e}")
        except KeyboardInterrupt:
            print("\n[!] Cancelled by user.")
    else:
        print("Execution skipped.")


if __name__ == "__main__":
    main()