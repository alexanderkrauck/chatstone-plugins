"""Immutable collector boundary. Raw records are nonindexed storage inputs."""
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

Role = Literal["user", "assistant", "tool", "system"]
PartKind = Literal["tool_call", "tool_result", "reasoning", "attachment", "oversize", "invalid"]


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    source: str
    host_id: str


@dataclass(frozen=True, slots=True)
class ParseLimits:
    max_text_bytes: int = 25_000_000
    max_attachment_bytes: int = 25_000_000
    max_archive_members: int = 1000
    max_archive_uncompressed_bytes: int = 250_000_000
    max_archive_member_bytes: int = 250_000_000


@dataclass(frozen=True, slots=True)
class Part:
    kind: PartKind
    text: str | None = None
    call_id: str | None = None
    name: str | None = None
    arguments_json: str | None = None
    sha256: str | None = None
    size: int | None = None
    content_type: str | None = None


@dataclass(frozen=True, slots=True)
class Attachment:
    sha256: str
    size: int
    content_type: str
    data: bytes | None
    oversize: bool


@dataclass(frozen=True, slots=True)
class NormalizedMessage:
    source: str
    host_id: str
    native_session_id: str
    native_id: str
    seq: int
    ts: datetime | None
    role: Role | None
    native_role: str | None
    native_source: str | None
    content: str
    parts: tuple[Part, ...]
    raw_hash: str
    content_hash: str
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ParsedRecord:
    message: NormalizedMessage
    attachments: tuple[Attachment, ...]
    raw_record: bytes


@dataclass(frozen=True, slots=True)
class ExtractedContent:
    content: str
    parts: tuple[Part, ...]
    attachments: tuple[Attachment, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StoredRevision:
    revision: int
    raw_hash: str
    content_hash: str


@dataclass(frozen=True, slots=True)
class RevisionDecision:
    action: Literal["insert", "unchanged", "revision"]
    revision: int
