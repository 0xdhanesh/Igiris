from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
from typing import Callable

from .auth import write_password_verifier


MIN_PASSWORD_LENGTH = 12


def configure_password(path: str | Path, *, prompt: Callable[[str], str] = getpass.getpass) -> None:
    password = prompt("New Igris password: ")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    confirmation = prompt("Confirm Igris password: ")
    if password != confirmation:
        raise ValueError("Passwords do not match")
    write_password_verifier(path, password)


def main() -> None:
    parser = argparse.ArgumentParser(description="Set the local Igris unlock password")
    parser.add_argument(
        "--file",
        default=os.environ.get("IGRIS_PASSWORD_VERIFIER_FILE"),
        help="Owner-only password verifier file",
    )
    args = parser.parse_args()
    if not args.file:
        parser.error("--file or IGRIS_PASSWORD_VERIFIER_FILE is required")
    try:
        configure_password(args.file)
    except ValueError as exc:
        parser.error(str(exc))
    print(f"Igris password verifier updated: {args.file}")
