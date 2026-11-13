"""Narrow discovery and descriptor-relative, no-follow POSIX source opening.

Discovery is metadata only. Its results grant no authority: opening repeats the
policy and walks from a no-follow root descriptor, never a resolved pathname.
"""
from __future__ import annotations

import errno
import fnmatch
import os
import re
import stat
from contextlib import contextmanager
from pathlib import Path


class SourceDenied(ValueError):
    """Source is outside the safe path policy (no payload in error messages)."""


_PATTERNS = {
    "hermes": (".hermes/state.db",),
    "claude_code": (".claude/projects/**/*.jsonl",),
    "codex": (".codex/sessions/**/*.jsonl", ".codex/sessions/**/*.jsonl.zst"),
    "cowork": ("Library/Application Support/Claude/local-agent-mode-sessions/*/*/local_*/.claude/projects/**/*.jsonl",),
    "opencode": (".local/share/opencode/opencode.db",),
    "cursor_ide": ("Library/Application Support/Cursor/User/globalStorage/state.vscdb",),
    "copilot": (
        "Library/Application Support/Code/User/workspaceStorage/*/chatSessions/*.json",
        "Library/Application Support/Code/User/workspaceStorage/*/chatSessions/*.jsonl",
    ),
    "gemini_cli": (".gemini/tmp/*/chats/session-*.json",),
    "antigravity": (".gemini/antigravity-cli/brain/*/.system_generated/logs/transcript.jsonl",),
    "chatgpt": (),
}
_SECRET = re.compile(
    r"^\.?(?:auth(?:entication)?|credentials?|tokens?|oauth|env|"
    r"google_accounts|client_storage|id_rsa|id_ed25519|id_ecdsa|private[-_]key)(?:[._-]|$)"
    r"|(?:^|[._-])(?:oauth|audit[-_]key)(?:[._-]|$)"
    r"|\.(?:pem|key|p12|pfx)(?:\.|$)", re.IGNORECASE,
)
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def credential_name(name: str) -> bool:
    return bool(_SECRET.search(name))


def checked_path(path: Path) -> Path:
    """Validate lexical components before any filesystem payload acquisition."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or len(path.parts) > 64:
        raise SourceDenied("SOURCE_PATH_UNSAFE")
    if any(credential_name(part) for part in path.parts):
        raise SourceDenied("SOURCE_CREDENTIAL_NAME")
    return path


@contextmanager
def directory_anchor(path: Path):
    """Hold the actual directory reached without following any component link."""
    path = checked_path(path)
    fd = os.open("/", _DIRECTORY)
    try:
        for component in path.parts[1:]:
            child = os.open(component, _DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise SourceDenied("SOURCE_PATH_UNSAFE") from None
        raise
    finally:
        os.close(fd)


@contextmanager
def open_explicit(path: Path):
    """Read an explicitly supplied noncredential regular file, without symlinks.

    This is for export inputs, not automatic source discovery. SQLite must use
    its own WAL-aware opener rather than reading a transcript stream here.
    """
    path = checked_path(path)
    with directory_anchor(path.parent) as parent:
        metadata = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode):
            raise SourceDenied("SOURCE_NOT_REGULAR")
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                         dir_fd=parent)
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise SourceDenied("SOURCE_PATH_UNSAFE") from None
            raise
        try:
            acquired = os.fstat(fd)
            if not stat.S_ISREG(acquired.st_mode) or (acquired.st_dev, acquired.st_ino) != (
                metadata.st_dev, metadata.st_ino
            ):
                raise SourceDenied("SOURCE_CHANGED")
            with os.fdopen(fd, "rb", closefd=False) as handle:
                yield handle
        finally:
            os.close(fd)


def _matches(parts, pattern):
    if not pattern:
        return not parts
    if pattern[0] == "**":
        return _matches(parts, pattern[1:]) or bool(parts and _matches(parts[1:], pattern))
    return bool(parts and fnmatch.fnmatchcase(parts[0], pattern[0])
                and _matches(parts[1:], pattern[1:]))


def _patterns(source):
    if source not in _PATTERNS:
        raise SourceDenied("SOURCE_UNSUPPORTED")
    return tuple(tuple(pattern.split("/")) for pattern in _PATTERNS[source])


def discover_sources(home: Path, *, source: str, exclusions: tuple[str, ...] = ()) -> tuple[Path, ...]:
    home = checked_path(home)
    patterns = _patterns(source)
    found = set()

    def visit(fd, prefix, pattern):
        if len(prefix) > 64:
            raise SourceDenied("SOURCE_DEPTH_LIMIT")
        if not pattern:
            return
        if pattern[0] == "**":
            visit(fd, prefix, pattern[1:])
        with os.scandir(fd) as entries:
            for entry in entries:
                if credential_name(entry.name) or entry.is_symlink():
                    continue
                relative = (*prefix, entry.name)
                name = "/".join(relative)
                if any(fnmatch.fnmatchcase(name, x) or fnmatch.fnmatchcase(str(home / name), x)
                       for x in exclusions):
                    continue
                if pattern[0] != "**" and not fnmatch.fnmatchcase(entry.name, pattern[0]):
                    continue
                if len(pattern) == 1 and entry.is_file(follow_symlinks=False):
                    found.add(home / name)
                elif entry.is_dir(follow_symlinks=False):
                    try:
                        child = os.open(entry.name, _DIRECTORY, dir_fd=fd)
                    except OSError as error:
                        if error.errno in {errno.ENOENT, errno.ELOOP, errno.ENOTDIR}:
                            continue
                        raise
                    try:
                        visit(child, relative, pattern if pattern[0] == "**" else pattern[1:])
                    finally:
                        os.close(child)

    with directory_anchor(home) as root:
        for pattern in patterns:
            visit(root, (), pattern)
    return tuple(sorted(found))


@contextmanager
def open_source(path: Path, *, home: Path, source: str):
    home, path = checked_path(home), checked_path(path)
    try:
        relative = path.relative_to(home)
    except ValueError:
        raise SourceDenied("SOURCE_OUTSIDE_HOME") from None
    if not any(_matches(relative.parts, pattern) for pattern in _patterns(source)):
        raise SourceDenied("SOURCE_NOT_ALLOWLISTED")
    with open_explicit(path) as handle:
        yield handle
