"""Extract binary references before applying the searchable UTF-8 text cap.

Decode in bounded chunks; oversize payload bytes are discarded, not truncated
and uploaded. The input string itself is caller-owned and must be bounded by
an outer record/job limit. No file paths or URLs are fetched here.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import re

from .contracts import Attachment, ExtractedContent, ParseLimits, Part

_TOKEN = re.compile(
    r"data:(?P<mime>[^;,\s]*)(?:;[^,\s]*)?;base64,(?P<data>[^\s\"'<>()[\]{}]*)"
    r"|(?<![A-Za-z0-9+/=])(?P<bare>[A-Za-z0-9+/]{256,}={0,2})(?![A-Za-z0-9+/=])",
    re.IGNORECASE,
)
_CHUNK = 65_536  # divisible by 4; decoded temporary buffer <= 49,152 bytes


def _decode(encoded, cap):
    if len(encoded) % 4 or "=" in encoded[:-2]:
        raise ValueError("BINARY_INVALID")
    digest = hashlib.sha256()
    size = 0
    data = bytearray()
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    binary = False
    for start in range(0, len(encoded), _CHUNK):
        chunk = base64.b64decode(encoded[start:start + _CHUNK], validate=True)
        size += len(chunk)
        digest.update(chunk)
        if not binary:
            try:
                decoded = decoder.decode(chunk)
                binary = any(not c.isprintable() and c not in "\n\r\t" for c in decoded)
            except UnicodeDecodeError:
                binary = True
        if size <= cap:
            data.extend(chunk)
        else:
            data.clear()
    if not binary:
        try:
            decoder.decode(b"", final=True)
        except UnicodeDecodeError:
            binary = True
    return digest.hexdigest(), size, bytes(data) if size <= cap else None, binary


def text_digest(text):
    digest = hashlib.sha256()
    size = 0
    for start in range(0, len(text), _CHUNK):
        chunk = text[start:start + _CHUNK].encode("utf-8")
        size += len(chunk)
        digest.update(chunk)
    return size, digest.hexdigest()


def extract_binary(data: bytes, *, limits: ParseLimits) -> ExtractedContent:
    """Opaque SQLite BLOBs never undergo lossy text decoding."""
    size, digest = len(data), hashlib.sha256(data).hexdigest()
    oversize = size > limits.max_attachment_bytes
    mime = "application/octet-stream"
    part = Part(kind="oversize" if oversize else "attachment",
                sha256=digest, size=size, content_type=mime)
    attachment = Attachment(digest, size, mime, None if oversize else data, oversize)
    return ExtractedContent("", (part,), (attachment,),
                            ("ATTACHMENT_OVERSIZE",) if oversize else ())


def extract_content(text: str, *, limits: ParseLimits) -> ExtractedContent:
    if limits.max_text_bytes < 0 or limits.max_attachment_bytes < 0:
        raise ValueError("LIMIT_INVALID")
    parts, warnings = [], []
    attachments = {}

    def replace(match):
        explicit = match.group("bare") is None
        encoded = match.group("data") if explicit else match.group("bare")
        mime = (match.group("mime") or "application/octet-stream") if explicit else "application/octet-stream"
        try:
            sha, size, data, binary = _decode(encoded, limits.max_attachment_bytes)
        except (ValueError, binascii.Error):
            if not explicit:
                return match.group(0)
            parts.append(Part(kind="invalid", content_type=mime))
            warnings.append("BINARY_INVALID")
            return ""
        if not explicit and not binary:
            return match.group(0)
        oversize = size > limits.max_attachment_bytes
        parts.append(Part(kind="oversize" if oversize else "attachment",
                          sha256=sha, size=size, content_type=mime))
        attachments.setdefault(sha, Attachment(sha, size, mime, data, oversize))
        if oversize:
            warnings.append("ATTACHMENT_OVERSIZE")
        return ""

    content = _TOKEN.sub(replace, text)
    size, sha = text_digest(content)
    if size > limits.max_text_bytes:
        parts.append(Part(kind="oversize", sha256=sha, size=size, content_type="text/plain"))
        warnings.append("TEXT_OVERSIZE")
        content = ""
    return ExtractedContent(content, tuple(parts), tuple(attachments.values()),
                            tuple(dict.fromkeys(warnings)))
