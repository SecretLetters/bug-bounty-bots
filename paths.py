#!/usr/bin/env python3
"""Resolve the bounty-pipeline base directory and well-known subpaths.

Override the data directory with the BOUNTY_PIPELINE_DIR environment variable
or, on the top-level scripts, --base-dir. Otherwise the directory containing
these scripts is used (a typical install lands in ~/bounty-pipeline).

This module never contacts a target host. The only network it may use is a
git clone or pull of the public arkadiyt/bounty-targets-data repository.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

BOUNTY_TARGETS_URL = "https://github.com/arkadiyt/bounty-targets-data.git"
BOUNTY_TARGETS_NAME = "bounty-targets-data"
POC_IN_GITHUB_NAME = "poc-in-github"
STATE_NAME = "state"


def base_dir() -> Path:
    env = os.environ.get("BOUNTY_PIPELINE_DIR", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    return SCRIPT_DIR


def state_dir(root: Path | None = None) -> Path:
    return (root or base_dir()) / STATE_NAME


def bounty_targets_repo(root: Path | None = None) -> Path:
    return (root or base_dir()) / BOUNTY_TARGETS_NAME


def poc_in_github_repo(root: Path | None = None) -> Path:
    return (root or base_dir()) / POC_IN_GITHUB_NAME


def resolve_base(cli_value: Path | str | None) -> Path:
    """Resolve --base-dir if given, otherwise the env / script-dir default."""
    if cli_value:
        return Path(cli_value).expanduser().resolve()
    return base_dir()


def resolve_path(cli_value: Path | str | None, default: Path) -> Path:
    if cli_value:
        return Path(cli_value).expanduser().resolve()
    return Path(default).expanduser().resolve()


def ensure_bounty_targets(repo: Path | None = None, *, pull: bool = False) -> Path:
    """Clone arkadiyt/bounty-targets-data if missing; optionally git pull.

    Idempotent. A shallow clone is used on first install.
    """
    import shutil

    dest = Path(repo or bounty_targets_repo()).expanduser().resolve()
    git_dir = dest / ".git"
    if git_dir.exists():
        if pull:
            print(f"Updating bounty-targets-data at {dest} ...", file=sys.stderr)
            try:
                subprocess.check_call(
                    ["git", "-C", str(dest), "pull", "--ff-only"],
                    stdout=sys.stderr,
                )
            except subprocess.CalledProcessError as exc:
                print(f"git pull --ff-only failed in {dest}: {exc}", file=sys.stderr)
                raise SystemExit(1) from exc
        return dest
    if dest.exists() and not dest.is_dir():
        print(f"bounty-targets-data path exists but is not a directory: {dest}", file=sys.stderr)
        raise SystemExit(1)
    if dest.exists() and any(dest.iterdir()) and not git_dir.exists():
        print(
            f"{dest} exists but is not a git clone of {BOUNTY_TARGETS_URL}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if shutil.which("git") is None:
        print("git is required to clone bounty-targets-data.", file=sys.stderr)
        raise SystemExit(1)
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"Cloning {BOUNTY_TARGETS_URL} into {dest} ...", file=sys.stderr)
    try:
        # Full clone: watch.py diffs program/scope history over 24–72 hours and
        # checks first-seen dates. A depth-1 clone would make Section A empty
        # and can mis-label returning programs as new.
        subprocess.check_call(
            ["git", "clone", "--single-branch", BOUNTY_TARGETS_URL, str(dest)],
            stdout=sys.stderr,
        )
    except subprocess.CalledProcessError as exc:
        print(f"git clone failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    return dest
