#!/usr/bin/env python3
"""Install a validated rendered config with atomic replacement."""

from __future__ import annotations

import os
import stat
import sys


def main(argv: list[str]) -> int:
    args = argv[1:]
    allow_unsafe_parents = False
    if args and args[0] == "--allow-unsafe-parents":
        allow_unsafe_parents = True
        args = args[1:]

    if len(args) == 2 and args[0] == "--directory-check":
        return 0 if output_directory_can_be_used_safely(args[1], allow_unsafe_parents) else 2

    if len(args) == 2 and args[0] == "--parent-check":
        return 0 if allow_unsafe_parents or output_directory_parents_can_be_used_safely(args[1], True) else 2

    if len(args) == 4 and args[0] == "--metadata-check":
        uid = int(args[1])
        gid = int(args[2])
        mode = int(args[3], 8)
        return 0 if metadata_values_can_be_applied_safely(uid, gid, mode) else 1

    if len(args) != 2:
        print("usage: install-rendered-config.py [--allow-unsafe-parents] <source> <target>", file=sys.stderr)
        return 2

    source, target = args
    target_dir = os.path.dirname(os.path.abspath(target))
    if not output_directory_can_be_used_safely(target_dir, allow_unsafe_parents):
        return 2

    try:
        source_stat = os.lstat(source)
    except FileNotFoundError:
        print(f"source path must be a file: {source}", file=sys.stderr)
        return 2
    if not stat.S_ISREG(source_stat.st_mode):
        print(f"source path must be a file: {source}", file=sys.stderr)
        return 2
    target_stat = None
    try:
        target_stat = os.lstat(target)
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(target_stat.st_mode):
            print(f"output path must be a regular file: {target}", file=sys.stderr)
            return 2
        if not metadata_can_be_applied_safely(target_stat):
            print(
                f"output path metadata is not safe to preserve before replacement: {target}",
                file=sys.stderr,
            )
            return 2

    if target_stat is None:
        os.chmod(source, 0o644)
    else:
        if source_stat.st_uid != target_stat.st_uid or source_stat.st_gid != target_stat.st_gid:
            print(
                f"source metadata does not match existing output owner/group: {source}",
                file=sys.stderr,
            )
            return 2
        apply_target_metadata_before_replace(source, target_stat)
    os.replace(source, target)
    return 0


def output_directory_can_be_used_safely(path: str, allow_unsafe_parents: bool) -> bool:
    absolute_path = os.path.abspath(path)
    try:
        directory_stat = os.lstat(absolute_path)
    except FileNotFoundError:
        print(f"output directory must exist: {absolute_path}", file=sys.stderr)
        return False
    if not stat.S_ISDIR(directory_stat.st_mode):
        print(f"output directory must be a directory: {absolute_path}", file=sys.stderr)
        return False
    if not directory_metadata_can_be_used_safely(directory_stat):
        print(f"output directory metadata is not safe to use: {absolute_path}", file=sys.stderr)
        return False
    if not allow_unsafe_parents and not output_directory_parents_can_be_used_safely(absolute_path, False):
        return False
    return True


def output_directory_parents_can_be_used_safely(path: str, include_self: bool) -> bool:
    current = path if include_self else os.path.dirname(path)
    trusted_uids = trusted_parent_uids()
    while current and current != os.path.dirname(current):
        parent_stat = os.lstat(current)
        parent_mode = stat.S_IMODE(parent_stat.st_mode)
        if parent_stat.st_uid not in trusted_uids:
            print(f"output directory parent owner is not trusted: {current}", file=sys.stderr)
            return False
        if parent_mode & (stat.S_IWGRP | stat.S_IWOTH) and not parent_mode & stat.S_ISVTX:
            print(f"output directory parent metadata is not safe to use: {current}", file=sys.stderr)
            return False
        current = os.path.dirname(current)
    return True


def trusted_parent_uids() -> set[int]:
    return {0, os.geteuid(), os.stat("/").st_uid}


def directory_metadata_can_be_used_safely(directory_stat: os.stat_result) -> bool:
    mode = stat.S_IMODE(directory_stat.st_mode)
    if directory_stat.st_uid != os.geteuid() or directory_stat.st_gid != os.getegid():
        return False
    if not mode & stat.S_IWUSR or not mode & stat.S_IXUSR:
        return False
    if mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
        return False
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        return False
    return True


def metadata_can_be_applied_safely(target_stat: os.stat_result) -> bool:
    return metadata_values_can_be_applied_safely(
        target_stat.st_uid,
        target_stat.st_gid,
        stat.S_IMODE(target_stat.st_mode),
    )


def metadata_values_can_be_applied_safely(uid: int, gid: int, mode: int) -> bool:
    if uid != os.geteuid() or gid != os.getegid():
        return False
    if not mode & stat.S_IRUSR or not mode & stat.S_IROTH:
        return False
    if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        return False
    if mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
        return False
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        return False
    return True


def apply_target_metadata_before_replace(source: str, target_stat: os.stat_result) -> None:
    target_mode = stat.S_IMODE(target_stat.st_mode)
    source_stat = os.stat(source)
    if (source_stat.st_uid, source_stat.st_gid) != (target_stat.st_uid, target_stat.st_gid):
        os.chmod(source, 0)
        os.chown(source, target_stat.st_uid, target_stat.st_gid)
    os.chmod(source, target_mode)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
