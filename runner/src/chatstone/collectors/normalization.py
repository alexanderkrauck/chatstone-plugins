"""Canonical selected-record and semantic serialization shared by parsers."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import UTC, datetime

from .binary import extract_binary, extract_content
from .contracts import NormalizedMessage, ParsedRecord, Part


def canonical(value) -> bytes:
    def tagged(item):
        if isinstance(item, bytes):
            return {"$bytes_hex": item.hex()}
        raise TypeError("RAW_TYPE_UNSUPPORTED")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False, default=tagged).encode("utf-8")


def timestamp(value):
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(value, UTC)
    if not isinstance(value, str):
        raise TypeError("TIMESTAMP_INVALID")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("TIMESTAMP_NAIVE")
    return parsed.astimezone(UTC)


def record(*, raw, identity, session, native_id, seq, ts, native_role, text, limits,
           native_source=None, role_aliases=None, parts=(), warnings=(), tool_result=None):
    if identity.source == 'hermes' and isinstance(raw, dict) and raw.get('api_content') is None:
        raw = {key: value for key, value in raw.items() if key != 'api_content'}
    raw_bytes = canonical(raw)
    extracted = (extract_binary(text, limits=limits) if isinstance(text, bytes)
                 else extract_content(text, limits=limits))
    warnings = list(warnings) + list(extracted.warnings)
    role = (role_aliases or {}).get(native_role, native_role)
    if role not in {"user", "assistant", "tool", "system"}:
        role = None
        warnings.append("ROLE_UNKNOWN")
    try:
        stamp = timestamp(ts)
    except (ValueError, TypeError, OverflowError, OSError):
        stamp = None
        warnings.append("TIMESTAMP_INVALID")
    parts = tuple(parts)
    if tool_result is not None:
        parts += (Part(kind="tool_result", text=extracted.content,
                       call_id=tool_result[0], name=tool_result[1]),)
    parts += extracted.parts
    semantic = canonical({"native_role": native_role, "content": extracted.content,
                          "parts": [asdict(part) for part in parts]})
    return ParsedRecord(NormalizedMessage(
        source=identity.source, host_id=identity.host_id, native_session_id=session,
        native_id=native_id, seq=seq, ts=stamp, role=role, native_role=native_role,
        native_source=native_source, content=extracted.content, parts=parts,
        raw_hash=hashlib.sha256(raw_bytes).hexdigest(),
        content_hash=hashlib.sha256(semantic).hexdigest(),
        warnings=tuple(dict.fromkeys(warnings)),
    ), extracted.attachments, raw_bytes)
