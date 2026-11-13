"""Durable JSONL reconciliation, shared by native harness wakeups.

No daemon/scheduler; call capture from a native hook or explicit backfill. The
queue, file position and stable session ordering commit atomically. On changed
files the consumed prefix is hashed (O(prefix bytes), not reparsed): this detects
same-inode rewrites, including equal-length compaction in the middle. Unchanged
files cost stat only. Source files are never written; partial final lines wait.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from chatstone.collectors.contracts import ParseLimits, SourceIdentity
from chatstone.collectors.harnesses import _json, _zstd_chunks
from chatstone.collectors.live_harnesses import SkipRecord, project, session_payload
from chatstone.collectors.policy import checked_path, credential_name, open_explicit
from chatstone.collectors.wire import RequestError, decode_record

from .ingest import encode_record
from .transport import ClientError


def discover(root, source):
    root = checked_path(Path(root))
    if source not in ('claude_code', 'codex'):
        raise ValueError('SOURCE_UNSUPPORTED')
    found = []
    for directory, folders, files in os.walk(root, followlinks=False):
        folders[:] = sorted(d for d in folders if not credential_name(d) and not (Path(directory) / d).is_symlink())
        for name in sorted(files):
            path = Path(directory) / name
            if credential_name(name) or path.is_symlink() or name == 'audit.jsonl':
                continue
            if (source == 'claude_code' and name.endswith('.jsonl') or source == 'codex'
                    and name.startswith('rollout-') and name.endswith(('.jsonl', '.jsonl.zst'))):
                found.append(path)
    return tuple(sorted(found))


def prepare(spool):
    with spool._transaction():
        spool._db.execute('CREATE TABLE IF NOT EXISTS harness_files '
            '(identity TEXT PRIMARY KEY, path TEXT, position INTEGER, prefix TEXT, context TEXT, '
            'size INTEGER, mtime INTEGER, ctime INTEGER)')
        spool._db.execute('CREATE TABLE IF NOT EXISTS harness_ids '
            '(session TEXT, native TEXT, seq INTEGER, PRIMARY KEY(session,native), UNIQUE(session,seq))')
        spool._db.execute('CREATE TABLE IF NOT EXISTS harness_versions '
            '(session TEXT, native TEXT, fingerprint TEXT, PRIMARY KEY(session,native,fingerprint))')
        spool._db.execute('CREATE TABLE IF NOT EXISTS harness_occurrences '
            '(identity TEXT, native TEXT, occurrence INTEGER, PRIMARY KEY(identity,native))')
        spool._db.execute('CREATE TABLE IF NOT EXISTS harness_skips '
            '(identity TEXT, position INTEGER, digest TEXT, cause TEXT, PRIMARY KEY(identity,position))')
        if 'record_type' not in {r[1] for r in spool._db.execute('PRAGMA table_info(harness_skips)')}:
            spool._db.execute("ALTER TABLE harness_skips ADD COLUMN record_type TEXT NOT NULL DEFAULT 'legacy'")
        spool._db.execute('CREATE TABLE IF NOT EXISTS harness_sessions(native TEXT PRIMARY KEY,payload TEXT,sent TEXT)')
        spool._db.execute('CREATE TABLE IF NOT EXISTS harness_parser(version INTEGER)')
        if spool._db.execute('SELECT version FROM harness_parser').fetchone() != (2,):
            # Keep install, queue and seen fingerprints. Re-read old parser skips
            # and populate missing session metadata without resending messages.
            spool._db.execute("UPDATE harness_files SET position=0,prefix=?,context='{}',size=-1", (hashlib.sha256(b'').hexdigest(),))
            spool._db.execute('DELETE FROM harness_skips')
            spool._db.execute('DELETE FROM harness_parser')
            spool._db.execute('INSERT INTO harness_parser VALUES(2)')


def record_name(raw):
    def tag(value):
        return value if isinstance(value, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}', value) else 'invalid_type'
    name = tag(raw.get('type')) if isinstance(raw, dict) else 'invalid_object'
    if isinstance(raw, dict):
        child = raw.get('payload')
        if name in ('response_item', 'event_msg') and isinstance(child, dict):
            name += '/'+tag(child.get('type'))
        elif name == 'attachment' and isinstance(raw.get('attachment'), dict):
            name += '/'+tag(raw['attachment'].get('type'))
        elif name == 'system' and raw.get('subtype'):
            name += '/'+tag(raw['subtype'])
    return name


def store_session(spool, value):
    if value is None:
        return
    previous = spool._db.execute('SELECT payload FROM harness_sessions WHERE native=?', (value['native_session_id'],)).fetchone()
    if previous:
        old = json.loads(previous[0])
        merged = {k: value.get(k) if value.get(k) is not None else v for k, v in old.items()}
        ranks = {'first_prompt': 1, 'summary': 2, 'custom': 3}
        if ranks.get(old['meta'].get('title_source'), 0) > ranks.get(value['meta'].get('title_source'), 0):
            merged['title'], merged['meta'] = old['title'], {**value['meta'], 'title_source': old['meta'].get('title_source')}
        from datetime import datetime
        for field, chooser in (('started_at', min), ('ended_at', max)):
            stamps = [v for v in (old.get(field), value.get(field)) if v]
            merged[field] = chooser(stamps, key=datetime.fromisoformat) if stamps else None
        value = merged
    spool._db.execute('INSERT INTO harness_sessions VALUES(?,?,NULL) ON CONFLICT(native) '
                      'DO UPDATE SET payload=excluded.payload',
                      (value['native_session_id'], json.dumps(value, sort_keys=True, separators=(',', ':'))))


def retry_skipped(spool):
    """Explicit operator retry after a parser/transport upgrade; seen IDs remain."""
    prepare(spool)
    with spool._transaction():
        spool._db.execute('UPDATE harness_files SET position=0,prefix=?,context=\'{}\',size=-1 '
            'WHERE identity IN (SELECT identity FROM harness_skips)', (hashlib.sha256(b'').hexdigest(),))


def _prefix(handle, length):
    digest, left = hashlib.sha256(), length
    handle.seek(0)
    while left:
        block = handle.read(min(65536, left))
        if not block:
            return None
        digest.update(block)
        left -= len(block)
    return digest


@contextmanager
def _decoded(handle, compressed, limits):
    if not compressed:
        yield handle
        return
    # Archived compressed files are immutable snapshots, with durable positions
    # in the decompressed stream. libzstd must be bundled by the final runner.
    with tempfile.TemporaryFile() as decoded:
        for block in _zstd_chunks(iter(lambda: handle.read(65536), b''), limits.max_archive_uncompressed_bytes):
            decoded.write(block)
        decoded.seek(0)
        yield decoded


def capture(spool, root, *, attachment_roots=(), limits=None, max_lines=2048, paths=None, cursor_prefix=''):
    """One bounded pass. Failures in queue/disk/network NEVER become skips.

    Skips retain content-free cause, digest and position. A rewritten/repaired
    file replays them. max_lines bounds work, not the lifetime source size.
    """
    limits = limits or ParseLimits()
    prepare(spool)
    result = {'admitted': 0, 'skipped': 0, 'lines': 0, 'files': 0, 'resets': 0}
    identity = SourceIdentity(spool.source, spool.host)
    for path in (discover(root, spool.source) if paths is None else paths):
        if result['lines'] >= max_lines:
            break
        with open_explicit(path) as source:
            info = os.fstat(source.fileno())
            key = cursor_prefix+f'{info.st_dev}:{info.st_ino}'
            previous = spool._db.execute('SELECT position,prefix,context,size,mtime,ctime FROM harness_files WHERE identity=?', (key,)).fetchone()
            if previous and previous[3:] == (info.st_size, info.st_mtime_ns, info.st_ctime_ns):
                continue
            with _decoded(source, path.name.endswith('.zst'), limits) as handle:
                position, context, digest = 0, {}, hashlib.sha256()
                if previous:
                    position, expected, serialized = previous[:3]
                    digest = _prefix(handle, position)
                    if digest is None or digest.hexdigest() != expected:
                        position, context, digest = 0, {}, hashlib.sha256()
                        result['resets'] += 1
                    else:
                        context = json.loads(serialized)
                handle.seek(position)
                reset_occurrences = position == 0
                result['files'] += 1
                while result['lines'] < max_lines:
                    start = handle.tell()
                    line = handle.readline(min(limits.max_archive_member_bytes, 32 * 1024 * 1024) + 1)
                    if not line:
                        break
                    oversize = len(line) > min(limits.max_archive_member_bytes, 32 * 1024 * 1024)
                    row_hash = hashlib.sha256(line)
                    digest.update(line)
                    while line and not line.endswith(b'\n') and oversize:
                        line = handle.readline(65536)
                        row_hash.update(line)
                        digest.update(line)
                    if not line.endswith(b'\n'):
                        # Do not consume incomplete/oversize partial records.
                        break
                    end = handle.tell()
                    records, cause, updated = [], None, context
                    record_type = 'invalid_json'
                    try:
                        if oversize:
                            raise SkipRecord('LINE_OVERSIZE')
                        raw, warnings = _json(line)
                        if warnings:
                            raise SkipRecord('JSON_INVALID')
                        record_type = record_name(raw)
                        records, updated, cause = project(raw, source=identity, path=path,
                            context=context, limits=limits, attachment_roots=attachment_roots)
                        # Validate the exact wire boundary before durable admission.
                        for parsed in records:
                            decode_record(encode_record(parsed))
                            # Preflight the existing upload-envelope bound too;
                            # a too-large raw frame belongs in the skip ledger,
                            # never in a queue that can permanently block later rows.
                            try:
                                spool._prepare(parsed)
                            except ClientError as error:
                                if error.code not in ('REQUEST_TOO_LARGE', 'INVALID_REQUEST'):
                                    raise
                                raise SkipRecord('UPLOAD_ENVELOPE_OVERSIZE') from None
                    except (SkipRecord, RequestError, UnicodeError, TypeError, KeyError, RecursionError) as error:
                        records, updated = [], context
                        cause = str(error) if isinstance(error, SkipRecord) else 'RECORD_INVALID'
                    # Per-row transaction includes all fragments. Queue full rolls
                    # back IDs/seen/cursor together, leaving the record retryable.
                    with spool._transaction():
                        if reset_occurrences:
                            spool._db.execute('DELETE FROM harness_occurrences WHERE identity=?', (key,))
                        for parsed in records:
                            message = parsed.message
                            if 'NATIVE_ID_DERIVED' in message.warnings:
                                occurrence = spool._db.execute('INSERT INTO harness_occurrences VALUES(?,?,1) '
                                    'ON CONFLICT(identity,native) DO UPDATE SET occurrence=occurrence+1 '
                                    'RETURNING occurrence', (key, message.native_id)).fetchone()[0]
                                message = replace(message, native_id=message.native_id + ':occurrence:' + str(occurrence))
                                parsed = replace(parsed, message=message)
                            seq_row = spool._db.execute('SELECT seq FROM harness_ids WHERE session=? AND native=?',
                                (message.native_session_id, message.native_id)).fetchone()
                            if seq_row:
                                seq = seq_row[0]
                            else:
                                seq = spool._db.execute('SELECT coalesce(max(seq),-1)+1 FROM harness_ids WHERE session=?',
                                    (message.native_session_id,)).fetchone()[0]
                                spool._db.execute('INSERT INTO harness_ids VALUES(?,?,?)',
                                    (message.native_session_id, message.native_id, seq))
                            parsed = replace(parsed, message=replace(message, seq=seq))
                            try:
                                prepared = spool._prepare(parsed)
                            except ClientError as error:
                                if error.code not in ('REQUEST_TOO_LARGE', 'INVALID_REQUEST'):
                                    raise
                                # Whole multi-fragment row must remain retryable,
                                # not partially admitted. Surface explicitly.
                                raise ClientError('HARNESS_RECORD_TOO_LARGE') from None
                            version = (message.native_session_id, message.native_id, prepared[1])
                            # Latest-only seen fingerprints cannot recognize an
                            # older revision on a full replay after rotation.
                            promote = getattr(spool, 'promote', None)
                            if promote is not None:
                                promote(message.native_session_id, message.native_id)
                            if spool._db.execute('SELECT 1 FROM harness_versions '
                                'WHERE session=? AND native=? AND fingerprint=?', version).fetchone():
                                continue
                            if spool._add_prepared(prepared):
                                result['admitted'] += 1
                            spool._db.execute('INSERT INTO harness_versions VALUES(?,?,?)', version)
                        if records:
                            for record in records:
                                meta = json.loads(record.message.native_source)
                                store_session(spool, session_payload(updated, spool.source, path, session=record.message.native_session_id,
                                              kind=meta.get('kind'), parent=meta.get('parent')))
                        else:
                            store_session(spool, session_payload(updated, spool.source, path))
                        skip_key = key.removeprefix('live:')
                        if cause:
                            spool._db.execute('INSERT OR REPLACE INTO harness_skips VALUES(?,?,?,?,?)',
                                (skip_key, start, row_hash.hexdigest(), cause, record_type))
                            result['skipped'] += 1
                        else:
                            spool._db.execute('DELETE FROM harness_skips WHERE identity=? AND position=?', (skip_key, start))
                        # Do not mark the file unchanged until we reached EOF.
                        done = end == handle.seek(0, os.SEEK_END)
                        handle.seek(end)
                        spool._db.execute('INSERT OR REPLACE INTO harness_files VALUES(?,?,?,?,?,?,?,?)',
                            (key, str(path), end, digest.hexdigest(), json.dumps(updated),
                             info.st_size if done else -1, info.st_mtime_ns, info.st_ctime_ns))
                    context = updated
                    reset_occurrences = False
                    result['lines'] += 1
    return result
