"""Bounded explicit Claude Code/Cowork, Codex and Gemini CLI input parsers.

Synthetic-tested variants only; see the lane evidence README for the shape
matrix. No discovery, URL fetching, path attachment reads or private-store
access. Cowork uses only an explicitly designated .claude/projects JSONL.

JSONL is incremental; Gemini JSON is bounded then loaded as one document.
ParseLimits archive fields bound total bytes, line/document bytes and physical
lines/emitted records respectively. A hard 64 MiB line/document ceiling and
8 MiB zstd window also apply. Fatal quotas/decompression/identity errors may
follow an already-yielded prefix: callers MUST consume to EOF and surface coded
failures; an identity rejection terminates that input, never skips a record.

Native identifiers are exact strings, not stripped, normalized or deduplicated.
The generated message/session grammars below are reserved globally across these
parsers and files, even when no colliding generated record is present. A native
match raises NATIVE_ID_RESERVED / NATIVE_SESSION_ID_RESERVED before that row (or
any of its fragments) is yielded. Other repeated native IDs remain revisions;
missing/invalid IDs retain deterministic fallbacks and DERIVED warnings.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

from .binary import extract_content
from .contracts import ParsedRecord, ParseLimits, Part, SourceIdentity
from .normalization import canonical, record
from .policy import SourceDenied, checked_path, open_explicit


class HarnessRejected(ValueError):
    """Coded input, identity or decompression failure; no contents in errors."""


def _validate(limits):
    for value in (limits.max_text_bytes, limits.max_attachment_bytes,
                  limits.max_archive_member_bytes, limits.max_archive_uncompressed_bytes,
                  limits.max_archive_members):
        if type(value) is not int or value < 0:
            raise HarnessRejected("LIMIT_INVALID")


def _chunks(handle, cap):
    count = 0
    while chunk := handle.read(min(65_536, cap - count + 1)):
        count += len(chunk)
        if count > cap:
            raise HarnessRejected("SOURCE_SIZE_LIMIT")
        yield chunk


def _lines(chunks, limits):
    """Retain at most a line cap; drain/hash oversized lines in bounded chunks."""
    cap = min(limits.max_archive_member_bytes, 64 * 1024 * 1024)
    data, digest, size, ordinal = bytearray(), hashlib.sha256(), 0, 0
    for chunk in chunks:
        pieces = chunk.split(b"\n")
        for index, piece in enumerate(pieces):
            size += len(piece)
            digest.update(piece)
            if size <= cap:
                data.extend(piece)
            else:
                data.clear()
            if index == len(pieces) - 1:
                continue
            ordinal += 1
            if ordinal > limits.max_archive_members:
                raise HarnessRejected("SOURCE_RECORD_LIMIT")
            yield ordinal, bytes(data) if size <= cap else None, size, digest.hexdigest()
            data, digest, size = bytearray(), hashlib.sha256(), 0
    if size:
        ordinal += 1
        if ordinal > limits.max_archive_members:
            raise HarnessRejected("SOURCE_RECORD_LIMIT")
        yield ordinal, bytes(data) if size <= cap else None, size, digest.hexdigest()


def _json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def invalid(value):
        raise ValueError

    try:
        value = json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)
        # Catch surrogate strings, non-finite numbers and excessive nesting before
        # normalizer recursion, while retaining the exact rejected bytes below.
        canonical(value)
        stack = [(value, 0)]
        while stack:
            item, depth = stack.pop()
            if depth > 64:
                raise ValueError
            if isinstance(item, dict):
                stack.extend((v, depth + 1) for v in item.values())
            elif isinstance(item, list):
                stack.extend((v, depth + 1) for v in item)
        return value, []
    except (ValueError, UnicodeError, RecursionError):
        return {"invalid_json": data}, ["JSON_INVALID"]


def _zstd_chunks(chunks, cap):
    """Public libzstd streaming ABI; optional system library, loaded on demand.

    Input/output chunks <=64 KiB, decoded total <=cap, decoder window <=8 MiB.
    Concatenated frames are supported; incomplete frames/trailing junk fail.
    No one-shot decompression or advertised-content-size allocation is used.
    """
    import ctypes as c
    from ctypes.util import find_library

    class Buffer(c.Structure):
        _fields_ = [("data", c.c_void_p), ("size", c.c_size_t), ("pos", c.c_size_t)]

    import sys
    frozen = Path(getattr(sys, '_MEIPASS', '.'))
    bundled = next((p for p in (frozen/'libzstd.so.1', frozen/'libzstd.1.dylib') if p.is_file()), None)
    name = str(bundled) if bundled else find_library("zstd")
    if not name:
        raise HarnessRejected("ZSTD_UNAVAILABLE")
    try:
        lib = c.CDLL(name)
        signatures = {
            "ZSTD_createDCtx": ([], c.c_void_p),
            "ZSTD_freeDCtx": ([c.c_void_p], c.c_size_t),
            "ZSTD_DCtx_setParameter": ([c.c_void_p, c.c_int, c.c_int], c.c_size_t),
            "ZSTD_decompressStream": ([c.c_void_p, c.POINTER(Buffer), c.POINTER(Buffer)], c.c_size_t),
            "ZSTD_isError": ([c.c_size_t], c.c_uint),
        }
        for symbol, (arguments, result) in signatures.items():
            function = getattr(lib, symbol)
            function.argtypes, function.restype = arguments, result
    except (OSError, AttributeError):
        raise HarnessRejected("ZSTD_UNAVAILABLE") from None
    context = lib.ZSTD_createDCtx()
    if not context:
        raise HarnessRejected("ZSTD_UNAVAILABLE")
    try:
        # ZSTD_d_windowLogMax = 100 in the stable public zstd.h API.
        if lib.ZSTD_isError(lib.ZSTD_DCtx_setParameter(context, 100, 23)):
            raise HarnessRejected("ZSTD_UNAVAILABLE")
        count, hint = 0, 1
        for chunk in chunks:
            source = c.create_string_buffer(chunk)
            incoming = Buffer(c.cast(source, c.c_void_p), len(chunk), 0)
            while True:
                target = c.create_string_buffer(min(65_536, cap - count + 1))
                outgoing = Buffer(c.cast(target, c.c_void_p), len(target), 0)
                previous = incoming.pos
                hint = lib.ZSTD_decompressStream(context, c.byref(outgoing), c.byref(incoming))
                if lib.ZSTD_isError(hint):
                    raise HarnessRejected("ZSTD_INVALID")
                count += outgoing.pos
                if count > cap:
                    raise HarnessRejected("SOURCE_SIZE_LIMIT")
                if outgoing.pos:
                    yield target.raw[:outgoing.pos]
                if incoming.pos == incoming.size and (hint == 0 or outgoing.pos < outgoing.size):
                    break
                if incoming.pos == previous and not outgoing.pos:
                    raise HarnessRejected("ZSTD_INVALID")
        if hint:
            raise HarnessRejected("ZSTD_INVALID")
    finally:
        lib.ZSTD_freeDCtx(context)


def _entries(handle, limits, *, compressed=False):
    chunks = _chunks(handle, limits.max_archive_uncompressed_bytes)
    if compressed:
        chunks = _zstd_chunks(chunks, limits.max_archive_uncompressed_bytes)
    for ordinal, data, size, digest in _lines(chunks, limits):
        if data is None:
            yield ordinal, {"line_size": size, "line_sha256": digest}, ["LINE_OVERSIZE"]
        elif data.strip():
            raw, warnings = _json(data)
            yield ordinal, raw, warnings


# Global across these parsers/files, not a per-input seen set. Full-string,
# case-sensitive ASCII decimal ordinals: no signs or leading zeroes. The split
# prefix is nonempty and may contain any character (including newlines).
_RESERVED_MESSAGE_ID = re.compile(
    r"(?:line:[1-9][0-9]*|message:(?:0|[1-9][0-9]*)|document|"
    r".+:tool_result:(?:0|[1-9][0-9]*))", re.DOTALL,
)
_RESERVED_SESSION_ID = re.compile(r"path-sha256:[0-9a-f]{64}")


def _id(value, fallback, warnings, *, session=False):
    kind = "NATIVE_SESSION_ID" if session else "NATIVE_ID"
    reserved = _RESERVED_SESSION_ID if session else _RESERVED_MESSAGE_ID
    if isinstance(value, str) and value:
        if reserved.fullmatch(value):
            raise HarnessRejected(f"{kind}_RESERVED")
        return value
    warnings.append(f"{kind}_DERIVED")
    return fallback


def _session(path):
    return "path-sha256:" + hashlib.sha256(str(path).encode()).hexdigest()


def _string(value, warnings):
    if isinstance(value, (str, type(None))):
        return value
    warnings.append("FIELD_INVALID")
    return None


def _array(value, warnings):
    if isinstance(value, list):
        return value
    warnings.append("FIELD_INVALID")
    return []


def _cowork_raw(raw, warnings):
    """Omit known wrapper metadata, not matching keys in transcript/tool content."""
    if "JSON_INVALID" in warnings:
        data = raw["invalid_json"]
        warnings.append("RAW_OMITTED_UNPARSEABLE")
        return {"line_size": len(data), "line_sha256": hashlib.sha256(data).hexdigest()}
    omitted = {"accountEmail", "account_email", "systemPrompt", "system_prompt"}
    result = {key: value for key, value in raw.items() if key not in omitted}
    if isinstance(result.get("metadata"), dict):
        result["metadata"] = {k: v for k, v in result["metadata"].items() if k not in omitted}
    if result != raw:
        warnings.append("METADATA_OMITTED")
    return result



class _Content:
    def __init__(self, limits):
        self.limits = limits
        self.text = []
        self.parts = []
        self.attachments = []
        self.warnings = []

    def inline(self, mime, data):
        mime = _string(mime, self.warnings)
        data = _string(data, self.warnings)
        if (mime is None or data is None
                or re.fullmatch(r"[\w.+-]+/[\w.+-]+", mime, flags=re.ASCII) is None
                or re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", data) is None):
            self.parts.append(Part(kind="invalid"))
            self.warnings.append("BINARY_INVALID")
            return
        extracted = extract_content(f"data:{mime};base64,{data}", limits=self.limits)
        self.parts.extend(extracted.parts)
        self.attachments.extend(extracted.attachments)
        self.warnings.extend(extracted.warnings)

    def part(self, kind, text, **kwargs):
        text = _string(text, self.warnings)
        kwargs = {key: _string(value, self.warnings) for key, value in kwargs.items()}
        extracted = extract_content(text or "", limits=self.limits)
        self.parts.extend(extracted.parts)
        self.attachments.extend(extracted.attachments)
        self.warnings.extend(extracted.warnings)
        field = "arguments_json" if kind == "tool_call" else "text"
        self.parts.append(Part(kind=kind, **{field: extracted.content}, **kwargs))

    def read(self, value):
        if isinstance(value, str):
            self.text.append(value)
        elif isinstance(value, list):
            for block in value:
                if not isinstance(block, dict):
                    self.warnings.append("PART_UNSUPPORTED")
                    continue
                kind = _string(block.get("type"), self.warnings)
                if kind in {"text", "input_text", "output_text"}:
                    self.read(block.get("text"))
                elif kind == "input_image":
                    url = block.get("image_url")
                    if isinstance(url, str) and url.lower().startswith("data:"):
                        match = re.fullmatch(r"data:([^;,]+);base64,(.*)", url,
                                             re.IGNORECASE | re.DOTALL)
                        if match:
                            self.inline(*match.groups())
                        else:
                            self.parts.append(Part(kind="invalid"))
                            self.warnings.append("BINARY_INVALID")
                    else:
                        self.warnings.append("ATTACHMENT_REFERENCE_UNREAD")
                elif kind == "thinking":
                    self.part("reasoning", block.get("thinking", ""))
                elif kind == "tool_use":
                    self.part("tool_call", canonical(block.get("input")).decode(),
                              call_id=block.get("id"), name=block.get("name"))
                elif kind == "image" and isinstance(block.get("source"), dict):
                    source = block["source"]
                    if source.get("type") == "base64":
                        self.inline(source.get("media_type"), source.get("data"))
                    else:
                        self.warnings.append("ATTACHMENT_REFERENCE_UNREAD")
                else:
                    self.warnings.append("PART_UNSUPPORTED")
        elif value is not None:
            self.warnings.append("CONTENT_INVALID")

    def gemini(self, value, *, result=False):
        if not isinstance(value, list):
            self.read(value)
            return
        for block in value:
            if not isinstance(block, dict):
                self.warnings.append("PART_UNSUPPORTED")
            elif "text" in block:
                self.read(block["text"])
            elif isinstance(block.get("inlineData"), dict):
                data = block["inlineData"]
                self.read([{"type": "image", "source": {"type": "base64",
                           "media_type": data.get("mimeType"), "data": data.get("data")}}])
            elif result and isinstance(block.get("functionResponse"), dict):
                self.read(canonical(block["functionResponse"].get("response")).decode())
            else:
                self.warnings.append("PART_UNSUPPORTED")

    def emit(self, **kwargs):
        if kwargs.get("tool_result") is not None:
            kwargs["tool_result"] = tuple(_string(v, self.warnings) for v in kwargs["tool_result"])
        parsed = record(text="\n".join(self.text), parts=self.parts,
                        warnings=self.warnings, limits=self.limits, **kwargs)
        attachments = {a.sha256: a for a in (*parsed.attachments, *self.attachments)}
        return replace(parsed, attachments=tuple(attachments.values()))


def parse_claude_code(path: Path, *, identity: SourceIdentity,
                      limits: ParseLimits) -> Iterator[ParsedRecord]:
    _validate(limits)
    path = checked_path(path)
    if path.suffix.lower() != ".jsonl" or path.name.lower() == "audit.jsonl":
        raise SourceDenied("SOURCE_NOT_ALLOWLISTED")
    if identity.source == "cowork" and not any(
        path.parts[i:i + 2] == (".claude", "projects") for i in range(len(path.parts) - 2)
    ):
        raise SourceDenied("SOURCE_NOT_ALLOWLISTED")
    sequences, emitted = defaultdict(int), 0
    with open_explicit(path) as handle:
        for ordinal, raw, warnings in _entries(handle, limits):
            wrapper = raw if isinstance(raw, dict) else {}
            if identity.source == "cowork":
                raw = _cowork_raw(wrapper, warnings) if isinstance(raw, dict) else raw
            message = wrapper.get("message")
            if not isinstance(message, dict):
                message = {}
                if not warnings:
                    warnings.append("RECORD_UNSUPPORTED")
            session = _id(wrapper.get("sessionId"), _session(path), warnings,
                          session=True)
            native = _id(wrapper.get("uuid"), f"line:{ordinal}", warnings)
            role = message.get("role")
            if not isinstance(role, (str, type(None))):
                role = None
                warnings.append("ROLE_INVALID")
            content = message.get("content", "")
            results = [(i, b) for i, b in enumerate(content) if isinstance(b, dict)
                       and b.get("type") == "tool_result"] if isinstance(content, list) else []
            ordinary = [b for b in content if not isinstance(b, dict)
                        or b.get("type") != "tool_result"] if results else content
            fragments = [(native, ordinary, None)] if ordinary or not results else []
            fragments += [(f'{native}:tool_result:{i}', b.get("content"), b)
                          for i, b in results]
            for native_id, value, result in fragments:
                emitted += 1
                if emitted > limits.max_archive_members:
                    raise HarnessRejected("SOURCE_RECORD_LIMIT")
                parsed = _Content(limits)
                parsed.warnings.extend(warnings)
                parsed.read(value)
                if result is not None:
                    parsed.warnings.append("NATIVE_ID_DERIVED")
                seq = sequences[session]
                sequences[session] += 1
                yield parsed.emit(raw=raw, identity=identity, session=session,
                                  native_id=native_id, seq=seq, ts=wrapper.get("timestamp"),
                                  native_role=role,
                                  role_aliases={role: "tool"} if result is not None else None,
                                  tool_result=(result.get("tool_use_id"), None)
                                  if result is not None else None)



def parse_codex(path: Path, *, identity: SourceIdentity,
                limits: ParseLimits) -> Iterator[ParsedRecord]:
    _validate(limits)
    path = checked_path(path)
    if not str(path).lower().endswith((".jsonl", ".jsonl.zst")):
        raise SourceDenied("SOURCE_NOT_ALLOWLISTED")
    session, derived_session = _session(path), True
    sequences = defaultdict(int)
    with open_explicit(path) as handle:
        for ordinal, raw, warnings in _entries(handle, limits, compressed=path.suffix.lower() == ".zst"):
            wrapper = raw if isinstance(raw, dict) else {}
            payload = wrapper.get("payload")
            if not isinstance(payload, dict):
                payload = {}
            category = wrapper.get("type")
            if category == "session_meta":
                session = _id(payload.get("id"), _session(path), warnings,
                              session=True)
                derived_session = not isinstance(payload.get("id"), str) or not payload["id"]
            parsed = _Content(limits)
            parsed.warnings.extend(warnings)
            if derived_session:
                parsed.warnings.append("NATIVE_SESSION_ID_DERIVED")
            native = _id(payload.get("id") if category == "response_item" else None,
                         f"line:{ordinal}", parsed.warnings)
            kind = _string(payload.get("type"), parsed.warnings)
            role, aliases, result = None, None, None
            if category == "response_item":
                role = payload.get("role") if kind == "message" else kind
                if kind == "message":
                    parsed.read(payload.get("content"))
                elif kind in {"function_call", "custom_tool_call"}:
                    arguments = (payload.get("arguments", "") if kind == "function_call"
                                 else canonical(payload.get("input")).decode())
                    parsed.part("tool_call", arguments,
                                call_id=payload.get("call_id"), name=payload.get("name"))
                    aliases = {kind: "assistant"}
                elif kind in {"function_call_output", "custom_tool_call_output"}:
                    output = payload.get("output", "")
                    parsed.read(output if isinstance(output, (str, list)) else canonical(output).decode())
                    result = (payload.get("call_id"), payload.get("name"))
                    aliases = {kind: "tool"}
                elif kind == "reasoning":
                    for block in _array(payload.get("summary", []), parsed.warnings):
                        if isinstance(block, dict) and block.get("type") == "summary_text":
                            parsed.part("reasoning", block.get("text", ""))
                        else:
                            parsed.warnings.append("PART_UNSUPPORTED")
                    aliases = {kind: "assistant"}
                else:
                    parsed.warnings.append("RECORD_UNSUPPORTED")
            else:
                parsed.warnings.append("RECORD_METADATA" if category == "session_meta" else
                                       "EVENT_UNPROJECTED" if category == "event_msg" else
                                       "RECORD_UNSUPPORTED")
            if not isinstance(role, (str, type(None))):
                role = None
                parsed.warnings.append("ROLE_INVALID")
            seq = sequences[session]
            sequences[session] += 1
            yield parsed.emit(raw=raw, identity=identity, session=session, native_id=native,
                              seq=seq, ts=wrapper.get("timestamp"), native_role=role,
                              role_aliases=aliases, tool_result=result)


def parse_gemini(path: Path, *, identity: SourceIdentity,
                 limits: ParseLimits) -> Iterator[ParsedRecord]:
    _validate(limits)
    path = checked_path(path)
    if path.suffix.lower() != ".json" or path.name.lower() == "logs.json":
        raise SourceDenied("SOURCE_NOT_ALLOWLISTED")
    cap = min(limits.max_archive_member_bytes, limits.max_archive_uncompressed_bytes,
              64 * 1024 * 1024)
    with open_explicit(path) as handle:
        data = b"".join(_chunks(handle, cap))
    document, warnings = _json(data)
    root = document if isinstance(document, dict) else {}
    messages = root.get("messages")
    session = _id(root.get("sessionId"), _session(path), warnings,
                  session=True)
    if not isinstance(messages, list):
        if limits.max_archive_members == 0:
            raise HarnessRejected("SOURCE_RECORD_LIMIT")
        parsed = _Content(limits)
        parsed.warnings.extend([*warnings, "RECORD_UNSUPPORTED", "NATIVE_ID_DERIVED"])
        yield parsed.emit(raw=document, identity=identity, session=session, native_id="document",
                          seq=0, ts=None, native_role=None)
        return
    if len(messages) > limits.max_archive_members:
        raise HarnessRejected("SOURCE_RECORD_LIMIT")
    metadata = {key: value for key, value in root.items() if key != "messages"}
    seq = 0
    for ordinal, message in enumerate(messages):
        if seq >= limits.max_archive_members:
            raise HarnessRejected("SOURCE_RECORD_LIMIT")
        raw = {"session": metadata, "message": message}
        fields = message if isinstance(message, dict) else {}
        parsed = _Content(limits)
        parsed.warnings.extend(warnings)
        if not isinstance(message, dict):
            parsed.warnings.append("RECORD_UNSUPPORTED")
        native = _id(fields.get("id"), f"message:{ordinal}", parsed.warnings)
        role = fields.get("type")
        if not isinstance(role, (str, type(None))):
            role = None
            parsed.warnings.append("ROLE_INVALID")
        parsed.gemini(fields.get("content"))
        for thought in _array(fields.get("thoughts", []), parsed.warnings):
            if isinstance(thought, dict):
                parsed.part("reasoning", "\n".join(thought[k] for k in ("subject", "description")
                                                   if isinstance(thought.get(k), str)))
            else:
                parsed.warnings.append("PART_UNSUPPORTED")
        calls = _array(fields.get("toolCalls", []), parsed.warnings)
        for call in calls:
            if isinstance(call, dict):
                parsed.part("tool_call", canonical(call.get("args")).decode(),
                            call_id=call.get("id"), name=call.get("name"))
            else:
                parsed.warnings.append("TOOL_CALL_INVALID")
        yield parsed.emit(raw=raw, identity=identity, session=session, native_id=native,
                          seq=seq, ts=fields.get("timestamp"), native_role=role,
                          role_aliases={"gemini": "assistant"})
        seq += 1
        for index, call in enumerate(calls):
            if not isinstance(call, dict) or "result" not in call:
                continue
            if seq >= limits.max_archive_members:
                raise HarnessRejected("SOURCE_RECORD_LIMIT")
            result = _Content(limits)
            result.warnings.extend([*warnings, "NATIVE_ID_DERIVED"])
            value = call["result"]
            result.gemini(value if isinstance(value, (str, list)) else canonical(value).decode(),
                          result=True)
            yield result.emit(raw=raw, identity=identity, session=session,
                              native_id=f"{native}:tool_result:{index}", seq=seq,
                              ts=fields.get("timestamp"), native_role=role,
                              role_aliases={role: "tool"},
                              tool_result=(call.get("id"), call.get("name")))
            seq += 1
