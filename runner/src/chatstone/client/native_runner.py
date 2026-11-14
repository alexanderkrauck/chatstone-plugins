"""Bounded native hook runner. No harness config contains credentials."""
from __future__ import annotations

import argparse
import fcntl
import getpass
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import warnings
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from .harness_capture import capture, discover, prepare, retry_skipped
from .ingest import IngestClient, encode_ingest_json
from .native_product import ORIGIN, PRODUCT, VERSION
from .spool import Spool
from .transport import TOKEN, TOOL_NAMES, Client, ClientError, encode_json

SOURCES = ('claude_code', 'codex')


def metadata_only(value):
    if isinstance(value, dict):
        return {k: None if k == 'data_base64' else metadata_only(v) for k, v in value.items()}
    if isinstance(value, list):
        return [metadata_only(v) for v in value]
    return value


class NativeSpool(Spool):
    """Only scheduling differs; persistence, retries and upload are shared."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.live = False
        with self._transaction():
            self._db.execute('CREATE TABLE IF NOT EXISTS native_priority(batch TEXT PRIMARY KEY, priority INTEGER)')
            self._db.execute('DELETE FROM native_priority WHERE batch NOT IN (SELECT batch FROM pending)')
            self._db.execute('CREATE TABLE IF NOT EXISTS native_identity(batch TEXT PRIMARY KEY,native TEXT)')
            self._db.execute('CREATE INDEX IF NOT EXISTS native_identity_key ON native_identity(native)')
            self._db.execute('DELETE FROM native_identity WHERE batch NOT IN (SELECT batch FROM pending)')
            self._db.execute('CREATE TABLE IF NOT EXISTS native_retry('
                'batch TEXT PRIMARY KEY,attempts INTEGER,code TEXT,bytes INTEGER,next_at REAL)')
            self._db.execute('DELETE FROM native_retry WHERE batch NOT IN (SELECT batch FROM pending)')
            self._db.execute('CREATE TABLE IF NOT EXISTS native_blobs('
                'batch TEXT,digest TEXT,PRIMARY KEY(batch,digest))')
            self._db.execute('DELETE FROM native_blobs WHERE batch NOT IN (SELECT batch FROM pending)')
            self._db.execute('CREATE TABLE IF NOT EXISTS native_health('
                'kind TEXT PRIMARY KEY,at REAL,code TEXT)')
            for batch, payload in self._db.execute('SELECT batch,payload FROM pending WHERE batch NOT IN (SELECT batch FROM native_identity)'):
                message = json.loads(payload)['records'][0]['message']
                self._db.execute('INSERT INTO native_identity VALUES(?,?)', (batch, json.dumps([message['native_session_id'], message['native_id']])))

    def _add_prepared(self, prepared):
        batch = super()._add_prepared(prepared)
        if batch:
            self._db.execute('INSERT INTO native_priority VALUES(?,?)', (batch, 0 if self.live else 1))
            self._db.execute('INSERT INTO native_identity VALUES(?,?)', (batch, json.dumps(json.loads(prepared[0]))))
        return batch

    def promote(self, session, native):
        if self.live:
            self._db.execute('UPDATE native_priority SET priority=0 WHERE batch IN '
                '(SELECT batch FROM native_identity WHERE native=?)', (json.dumps([session, native]),))

    def delivery_window(self):
        """Close the SQLite read cursor BEFORE any socket or lease handoff.

        A failed registration otherwise retains it in an exception traceback;
        sqlite3_close_v2 then leaves a read lock alive in another process's way.
        """
        rows, size = [], 0
        cursor = self._delivery_rows(8)
        try:
            for row in cursor:
                if rows and size+len(row[1]) > 32*1024*1024:
                    break
                rows.append(row)
                size += len(row[1])
        finally:
            cursor.close()
        return rows

    def status(self):
        value = super().status()
        if not self._db.execute("SELECT 1 FROM sqlite_master WHERE name='native_retry'").fetchone():
            return {**value, 'set_aside': {'count': 0, 'largest_bytes': 0, 'max_attempts': 0, 'reasons': {}},
                    'last_success': {}, 'last_failure': {}, 'active_pending': value['pending'], 'next_retry': None}
        count, largest, attempts = self._db.execute(
            "SELECT count(*),coalesce(max(bytes),0),coalesce(max(attempts),0) FROM native_retry "
            "WHERE (attempts>=3 OR code='UPLOAD_BODY_TIMEOUT') AND code!='AWAITING_RECEIPT'").fetchone()
        value['set_aside'] = {'count': count, 'largest_bytes': largest, 'max_attempts': attempts,
            'reasons': dict(self._db.execute("SELECT code,count(*) FROM native_retry "
                "WHERE (attempts>=3 OR code='UPLOAD_BODY_TIMEOUT') AND code!='AWAITING_RECEIPT' GROUP BY code"))}
        for kind in ('success', 'failure'):
            row = self._db.execute('SELECT at,code FROM native_health WHERE kind=?', (kind,)).fetchone()
            value['last_'+kind] = {'at': row[0], 'cause': row[1]} if row else {}
        value['active_pending'] = value['pending']-self._db.execute(
            'SELECT count(*) FROM native_retry WHERE next_at>?', (time.time(),)).fetchone()[0]
        row = self._db.execute('SELECT min(next_at) FROM native_retry').fetchone()
        value['next_retry'] = row[0]
        return value

    def defer(self, batch, error, size):
        # Keep original envelope, batch ID, seen state and every attachment byte.
        # Only conclusive operator-wide refusals stop the worker. An uncertain
        # ACK always replays its original ID, never a new logical upload.
        if error.code in {'INVALID_KEY', 'UNAUTHORIZED', 'FORBIDDEN', 'INGEST_DISABLED',
                          'INGEST_CAPACITY_EXCEEDED', 'QUOTA_EXCEEDED', 'SPOOL_IO', 'SPOOL_BUSY', 'SYNC_BUSY',
                          'SPOOL_FULL', 'SPOOL_CORRUPT', 'SPOOL_IDENTITY_MISMATCH'} or error.status in (401, 403, 507):
            raise error
        with self._transaction():
            row = self._db.execute('SELECT attempts FROM native_retry WHERE batch=?', (batch,)).fetchone()
            attempts = (row[0] if row else 0)+1
            pause = (30, 60)[attempts-1] if attempts < 3 else min(3600, 300*2**min(attempts-3, 4))
            if error.code == 'UPLOAD_BODY_TIMEOUT':
                pause = min(3600, 300*2**min(attempts-1, 4))
            if error.code == 'AWAITING_RECEIPT':
                pause = min(60, .25*2**min(attempts-1, 8))
            self._db.execute('INSERT OR REPLACE INTO native_retry VALUES(?,?,?,?,?)',
                (batch, attempts, error.code, getattr(error, 'upload_bytes', size), time.time()+pause))
            if error.code != 'AWAITING_RECEIPT':
                self._db.execute("INSERT OR REPLACE INTO native_health VALUES('failure',?,?)",
                                 (time.time(), error.code))

    def flush(self, client):
        """One ordered request; independent staging failures do not block its peers.

        A retained message never loses its original or passes an older revision
        of itself. Unrelated messages keep the existing live/history order.
        """
        if getattr(client, 'native_registered', None) != self.install_id:
            client.register_source(install_id=self.install_id, source=self.source, host=self.host)
            client.native_registered = self.install_id
        batches = []
        for batch, payload, receipt in self.delivery_window():
            if receipt in ('rejected', 'denied'):
                raise ClientError('QUOTA_EXCEEDED' if self.status()['errors'].get('QUOTA_EXCEEDED') else 'INVALID_RECORD')
            body = json.loads(payload)
            try:
                encode_ingest_json({'batches': metadata_only(batches+[body])})
            except ClientError as error:
                if error.code != 'REQUEST_TOO_LARGE':
                    raise
                if not batches:
                    batches.append(body)
                break
            batches.append(body)
        if not batches:
            return 0

        accepted = {batch['batch_id']: {row[0] for row in self._db.execute(
            'SELECT digest FROM native_blobs WHERE batch=?', (batch['batch_id'],))} for batch in batches}

        def stage(batch):
            known = accepted[batch['batch_id']]
            try:
                records = client._stage_attachments(self.install_id, batch['records'], None, staged=known)
                return {**batch, 'records': records}, None
            except ClientError as error:
                return batch, error

        # Never write SQLite from staging threads. A failed original holds back
        # its entire message, not the other messages in this window.
        with ThreadPoolExecutor(max_workers=4) as executor:
            outcomes = list(executor.map(stage, batches))
        # Persist positive blob acknowledgments before enqueue. Originals remain
        # unchanged until a final message receipt. One write group, not per part.
        new_blobs = [(batch, digest) for batch, digests in accepted.items() for digest in digests
            if not self._db.execute('SELECT 1 FROM native_blobs WHERE batch=? AND digest=?',
                                    (batch, digest)).fetchone()]
        if new_blobs:
            with self._transaction():
                self._db.executemany('INSERT OR IGNORE INTO native_blobs VALUES(?,?)', new_blobs)
        staged = []
        for batch, error in outcomes:
            if error is not None:
                self.defer(batch['batch_id'], error, len(encode_ingest_json(metadata_only(batch))))
            else:
                staged.append(batch)
        if not staged:
            return 0
        try:
            if len(staged) == 1:
                results = [client.enqueue(**staged[0])]
            else:
                result = client.enqueue_ordered(batches=staged)
                results = result.get('receipts')
            if not isinstance(results, list) or not 1 <= len(results) <= len(staged):
                raise ClientError('INVALID_ACK')
            checked = []
            for index, result in enumerate(results):
                receipt, code = self._receipt(result, staged[index]['batch_id'])
                if receipt != 'applied' and index != len(results)-1:
                    raise ClientError('INVALID_ACK')
                checked.append((staged[index]['batch_id'], receipt, code))
        except ClientError as error:
            for batch in staged:
                self.defer(batch['batch_id'], error, len(encode_ingest_json(batch)))
            return 0
        delivered, failure = 0, None
        with self._transaction():
            for batch, receipt, code in checked:
                if receipt == 'applied':
                    self._db.execute('DELETE FROM pending WHERE batch=?', (batch,))
                    self._db.execute('DELETE FROM native_retry WHERE batch=?', (batch,))
                    self._db.execute('DELETE FROM native_blobs WHERE batch=?', (batch,))
                    self._db.execute("INSERT OR REPLACE INTO native_health VALUES('success',?,NULL)", (time.time(),))
                    delivered += 1
                else:
                    self._db.execute('UPDATE pending SET receipt=?,code=? WHERE batch=?', (receipt, code, batch))
                    if code:
                        failure = ClientError(code)
        # Final-receipt polling also grows a pause; it must not busy-loop.
        for batch, receipt, code in checked:
            if receipt == 'queued':
                self.defer(batch, ClientError('AWAITING_RECEIPT'), 0)
        if failure:
            raise failure
        return delivered

    def _delivery_rows(self, limit):
        return self._db.execute('SELECT p.batch,p.payload,p.receipt FROM pending p '
            'LEFT JOIN native_priority n ON p.batch=n.batch '
            'JOIN native_identity i ON p.batch=i.batch '
            'LEFT JOIN native_retry r ON p.batch=r.batch '
            'WHERE (r.next_at IS NULL OR r.next_at<=?) AND NOT EXISTS '
            '(SELECT 1 FROM pending older JOIN native_identity oi ON older.batch=oi.batch '
            'WHERE oi.native=i.native AND older.seq<p.seq) '
            'ORDER BY coalesce(n.priority,1),CASE WHEN n.priority=0 THEN -p.seq ELSE p.seq END LIMIT ?',
            (time.time(), limit,))


def folder(kind):
    base = Path(os.environ.get('XDG_' + kind.upper() + '_HOME',
                str(Path.home() / ('.config' if kind == 'config' else '.local/share'))))
    path = base / PRODUCT / 'native'
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or path.stat().st_uid != os.getuid():
        raise ClientError('PRIVATE_DIRECTORY_UNSAFE')
    path.chmod(0o700)
    return path


def private_write(path, value):
    fd, name = tempfile.mkstemp(prefix='.private-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump(value, handle, separators=(',', ':'))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def private_read(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        raise ClientError('NOT_LOGGED_IN') from None
    with os.fdopen(fd) as handle:
        info = os.fstat(handle.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 65536):
            raise ClientError('KEY_FILE_UNSAFE')
        return json.load(handle)


def config_path(source):
    return folder('config') / (source + '.json')


def load(source):
    config = private_read(config_path(source))
    if (config.get('source') != source or not all(TOKEN.fullmatch(config.get(k, ''))
            for k in ('read_key', 'ingest_key'))):
        raise ClientError('KEY_SOURCE_MISMATCH')
    Client(config['origin'], allow_loopback_http=loopback())
    return config


def loopback():
    # Numeric loopback only, never disabled TLS on an Internet origin.
    return os.environ.get('CHATSTONE_TEST_LOOPBACK') == '1'


def roots(source):
    if source == 'claude_code':
        return [str(Path(os.environ.get('CLAUDE_CONFIG_DIR', str(Path.home()/'.claude'))) / 'projects')]
    home = Path(os.environ.get('CODEX_HOME', str(Path.home()/'.codex')))
    return [str(home/'sessions'), str(home/'archived_sessions')]


@contextmanager
def lease(source):
    fd = os.open(folder('data') / (source + '.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ClientError('SYNC_BUSY') from None
        yield
    finally:
        os.close(fd)


def open_spool(config):
    return NativeSpool(folder('data') / (config['source'] + '.sqlite'), source=config['source'],
                 host=config['device'], destination=config['origin'],
                 max_bytes=1_073_741_824, max_pending=10000)


def login(source):
    path = config_path(source)
    marker = path.with_suffix('.exchange')
    if path.exists() or marker.exists():
        raise ClientError('ALREADY_CONFIGURED_OR_EXCHANGE_UNCERTAIN')
    origin = os.environ.get('CHATSTONE_SERVER_URL', ORIGIN).rstrip('/')
    Client(origin, allow_loopback_http=loopback())
    # Require a controlling TTY before getpass can fall back to visible stdin.
    with open('/dev/tty', 'w') as tty, warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        code = getpass.getpass('One-time enrollment code: ', stream=tty)
    if not re.fullmatch(r'[A-Za-z0-9._-]{16,256}', code):
        raise ClientError('ENROLLMENT_CODE_INVALID')
    private_write(marker, {'started': True})
    with httpx.Client(timeout=15, trust_env=False, follow_redirects=False) as http:
        response = http.post(origin + '/api/v1/enroll', json={'code': code})
    del code
    if response.status_code != 200:
        marker.unlink()  # Conclusive refusal, not an ambiguous lost acknowledgment.
        raise ClientError('ENROLLMENT_REFUSED')
    value = response.json()
    if (value.get('sources') != [source]
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,62}', value.get('device', ''))
            or not all(TOKEN.fullmatch(value.get(k, '')) for k in ('ingest_key', 'read_key'))):
        raise ClientError('ENROLLMENT_SOURCE_MISMATCH')
    private_write(path, {k: value[k] for k in ('device', 'read_key', 'ingest_key')} |
                  {'origin': origin, 'source': source, 'roots': roots(source), 'attachment_roots': []})
    marker.unlink()
    wake(source, importing=True)
    print('Login complete. Existing history is importing in the background; you can close this terminal.\nCheck progress: '+command_name()+' status --source '+source)


def capture_recent(spool, files, config):
    """Independent durable tail cursor; history still reads every older byte.

    On upgrade, read a recent tail even of a partially imported file. Subsequent
    changes reconcile the entire prefix exactly like the history cursor.
    """
    from chatstone.collectors.policy import open_explicit

    prepare(spool)
    recent = [p for p in files[:8] if not p.name.endswith('.zst')]
    aligned = set()
    for path in recent:
        with open_explicit(path) as handle:
            info = os.fstat(handle.fileno())
            key = 'live:'+f'{info.st_dev}:{info.st_ino}'
            previous = spool._db.execute('SELECT position,prefix FROM harness_files WHERE identity=?', (key,)).fetchone()
            history = spool._db.execute('SELECT position,prefix FROM harness_files WHERE identity=?', (key.removeprefix('live:'),)).fetchone()
            if previous:
                if previous == history:
                    aligned.add(key.removeprefix('live:'))
                continue
            context = {}
            if config.get('source', spool.source) == 'codex':
                try:
                    first = json.loads(handle.readline(32*1024*1024))
                    if first.get('type') == 'session_meta':
                        payload = first['payload']
                        context = {'session': payload.get('id'), 'cwd': payload.get('cwd'),
                                   'parent': payload.get('parent_thread_id') or payload.get('forked_from_id')}
                except (ValueError, KeyError, TypeError):
                    pass  # Full history will diagnose malformed headers.
            # Select complete frames, not a byte suffix that can begin inside
            # an inline image followed by small bookkeeping records. At most
            # 64 initial frames and one bounded native-row window per file.
            window = max(0, info.st_size-32*1024*1024)
            handle.seek(window)
            tail = handle.read(32*1024*1024)
            end = len(tail)-(1 if tail.endswith(b'\n') else 0)
            start = window
            for _ in range(64):
                boundary = tail.rfind(b'\n', 0, end)
                if boundary < 0:
                    start = 0 if window == 0 else window+tail.find(b'\n')+1
                    break
                start = window+boundary+1
                end = boundary
            if start == 0:
                aligned.add(key.removeprefix('live:'))
            digest = hashlib.sha256()
            handle.seek(0)
            left = start
            while left:
                block = handle.read(min(left, 65536))
                digest.update(block)
                left -= len(block)
            with spool._transaction():
                spool._db.execute('INSERT INTO harness_files VALUES(?,?,?,?,?,?,?,?)',
                    (key, str(path), start, digest.hexdigest(), json.dumps(context), -1, 0, 0))
    result = capture(spool, None, paths=recent, max_lines=1024, cursor_prefix='live:',
                   attachment_roots=config.get('attachment_roots', ()))
    # Contiguous fresh coverage is also a history checkpoint. Re-parsing a
    # complete inline-image file doubles encoding/fsync work for no new data.
    with spool._transaction():
        for key in aligned:
            row = spool._db.execute('SELECT path,position,prefix,context,size,mtime,ctime FROM harness_files WHERE identity=?', ('live:'+key,)).fetchone()
            history = spool._db.execute('SELECT path,position,prefix,context,size,mtime,ctime FROM harness_files WHERE identity=?', (key,)).fetchone()
            if row and row != history:
                spool._db.execute('INSERT OR REPLACE INTO harness_files VALUES(?,?,?,?,?,?,?,?)', (key, *row))
                spool._db.execute('DELETE FROM harness_occurrences WHERE identity=?', (key,))
                spool._db.execute('INSERT INTO harness_occurrences SELECT ?,native,occurrence FROM harness_occurrences WHERE identity=?', (key, 'live:'+key))
    return result


def sync_metadata(spool, config, client):
    from .harness_capture import store_session

    if config['source'] == 'codex' and config['roots']:
        from chatstone.collectors.policy import open_explicit
        index = Path(config['roots'][0]).parent/'session_index.jsonl'
        if index.is_file() and not index.is_symlink():
            with open_explicit(index) as handle:
                for _ in range(100000):
                    line = handle.readline(65537)
                    if not line:
                        break
                    try:
                        entry = json.loads(line)
                        title = entry.get('thread_name')
                        previous = spool._db.execute('SELECT payload FROM harness_sessions WHERE native=?', (entry.get('id'),)).fetchone()
                        if previous and isinstance(title, str) and title.strip():
                            value = json.loads(previous[0])
                            value['title'] = title[:1000]
                            value['meta']['title_source'] = 'custom'
                            with spool._transaction():
                                store_session(spool, value)
                    except (ValueError, TypeError):
                        continue
    changed = []
    for native, payload, sent in spool._db.execute('SELECT native,payload,sent FROM harness_sessions'):
        digest = hashlib.sha256(payload.encode()).hexdigest()
        if sent != digest:
            value = json.loads(payload)
            try:
                encode_json({'install_id': spool.install_id, 'sessions': [v for v, d in changed]+[value]})
            except ClientError:
                break
            changed.append((value, digest))
        if len(changed) == 64:
            break
    if not changed:
        return
    if getattr(client, 'native_registered', None) != spool.install_id:
        client.register_source(install_id=spool.install_id, source=spool.source, host=spool.host)
        client.native_registered = spool.install_id
    receipt = client.update_sessions(install_id=spool.install_id, sessions=[v for v, d in changed])
    applied = receipt.get('applied')
    if not isinstance(applied, list) or any(n not in {v['native_session_id'] for v, d in changed} for n in applied):
        raise ClientError('INVALID_ACK')
    with spool._transaction():
        for value, digest in changed:
            if value['native_session_id'] in applied:
                spool._db.execute('UPDATE harness_sessions SET sent=? WHERE native=?', (digest, value['native_session_id']))
    return len(changed) == 64 and bool(applied)


def step(config, *, history=False, lines=256, client=None):
    with open_spool(config) as spool:
        prepare(spool)
        # Keep file scheduling outside the proven atomic per-record reader.
        files = [p for root in config['roots'] if Path(root).is_dir()
                 for p in discover(root, config['source'])]
        files.sort(key=lambda p: p.stat().st_mtime_ns, reverse=True)
        try:
            hint = private_read(folder('data')/(config['source']+'.hook')).get('transcript')
        except ClientError:
            hint = None
        if hint:
            files.sort(key=lambda p: str(p) != hint)
        deferred = False

        def collect(operation):
            nonlocal deferred
            before = spool.status()['pending']
            try:
                return operation()
            except ClientError as error:
                after = spool.status()['pending']
                if error.code != 'SPOOL_FULL' or not after:
                    raise
                # Capacity pressure is not a reason to abandon queued data.
                # Drain first; the failing frame's checkpoint never advanced.
                deferred = True
                return {'admitted': max(0, after-before), 'skipped': 0, 'lines': 0}

        spool.live = True
        fresh = collect(lambda: capture_recent(spool, files, config))
        spool.live = False
        total: dict[str, Any] = {key: fresh[key] for key in ('admitted', 'skipped', 'lines')}
        # Do not grow a multi-thousand-message backlog faster than the network.
        if spool.status()['active_pending'] < 128:
            result = collect(lambda: capture(spool, None, paths=files, attachment_roots=config.get('attachment_roots', ()),
                             max_lines=lines))
            for key in total:
                total[key] += result[key]
        total['deferred'] = deferred
        client = client or IngestClient(config['origin'], secret_getter=lambda: config['ingest_key'],
                              allow_loopback_http=loopback(), timeout=15)
        client.ordered = True
        summary = folder('data')/(config['source']+'.status')
        if not summary.exists():
            private_write(summary, snapshot(spool))
        total['delivered'] = spool.flush(client)
        if total['delivered']:
            private_write(folder('data')/(config['source']+'.upload'), {'at': int(time.time())})
        if spool.status()['active_pending'] < 128:
            total['metadata_more'] = sync_metadata(spool, config, client)
        total.update(spool.status())
        total.update(snapshot(spool))
        total['last_sync'] = int(time.time())
        private_write(folder('data') / (config['source'] + '.status'), total)
        return total


def snapshot(spool):
    value = spool.status()
    value['skips'] = dict(spool._db.execute('SELECT cause,count(*) FROM harness_skips GROUP BY cause'))
    value['skipped_types'] = dict(spool._db.execute('SELECT record_type,count(*) FROM harness_skips GROUP BY record_type'))
    value['found'] = spool._db.execute('SELECT count(*) FROM harness_ids').fetchone()[0]
    value['files'] = spool._db.execute('SELECT count(DISTINCT path) FROM harness_files').fetchone()[0]
    waiting = spool._db.execute('SELECT count(DISTINCT i.native) FROM native_identity i JOIN pending p ON i.batch=p.batch').fetchone()[0]
    value['uploaded'] = max(0, value['found']-waiting)
    return value


def read_snapshot(config):
    # DELETE-journal readers hold SHARED locks: even a read-only status poll can
    # make the writer's timeout=0 FULL-sync commit fail with SQLITE_BUSY. Status
    # reads only the atomically published content-free summary, never SQLite or
    # either worker/spool lease. A summary may lag an in-flight upload.
    try:
        value = private_read(folder('data')/(config['source']+'.status'))
    except ClientError as error:
        if error.code != 'NOT_LOGGED_IN':
            raise
        value = {'snapshot_pending': True}
    # A running 0.2.1 may have published the older summary shape.
    defaults = {'pending': 0, 'found': 0, 'uploaded': 0, 'files': 0,
        'skips': {}, 'skipped_types': {}, 'last_success': {}, 'last_failure': {},
        'next_retry': None, 'set_aside': {'count': 0, 'reasons': {},
            'largest_bytes': 0, 'max_attempts': 0}}
    return {**defaults, **value}


def status(config):
    value = read_snapshot(config)
    try:
        value['last'] = private_read(folder('data') / (config['source'] + '.status'))
    except ClientError:
        value['last'] = None
    value.update(version=VERSION, source=config['source'])
    for suffix in ('hook', 'upload', 'error'):
        try:
            saved = private_read(folder('data')/(config['source']+'.'+suffix))
        except ClientError:
            saved = {}
        value[suffix] = {k: saved[k] for k in ('at', 'event', 'cause') if k in saved}
    if value['error'].get('at', 0) > value['last_failure'].get('at', 0):
        value['last_failure'] = value['error']
    if not value['last_success']:
        value['last_success'] = value['upload']
    return value


def wake(source, *, hook=False, importing=False):
    # A hook records no prompt/assistant text. Its hint is only used after exact
    # discovery under the configured native roots; arbitrary paths are ignored.
    if hook:
        try:
            value = json.loads(sys.stdin.buffer.read(262145))
        except (ValueError, UnicodeError):
            value = {}
        event = value.get('hook_event_name', 'unknown') if isinstance(value, dict) else 'unknown'
        if not isinstance(event, str) or not re.fullmatch(r'[A-Za-z]{1,40}', event):
            event = 'unknown'
        transcript = value.get('agent_transcript_path') or value.get('transcript_path') if isinstance(value, dict) else None
        private_write(folder('data')/(source+'.hook'), {'at': int(time.time()), 'event': event,
                      'transcript': transcript if isinstance(transcript, str) and len(transcript) <= 4096 else None})
    load(source)
    command = ([sys.executable] if getattr(sys, 'frozen', False) else
               [sys.executable, '-m', 'chatstone.client.native_runner'])
    subprocess.Popen(command + ['backfill' if importing else 'sync', '--source', source, '--worker'], stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     # onefile children outlive the parent extraction directory.
                     env={**os.environ, 'PYINSTALLER_RESET_ENVIRONMENT': '1'},
                     start_new_session=True, close_fds=True)


def cause(error):
    code = error.code if isinstance(error, ClientError) else type(error).__name__.upper()
    if code == 'SPOOL_IO':
        detail = getattr(error.__context__, 'sqlite_errorname', '')
        if re.fullmatch(r'SQLITE_[A-Z_]{1,64}', detail):
            code += ':'+detail
    return code


def transient(error):
    if isinstance(error, ClientError) and error.code == 'SPOOL_IO':
        return getattr(error.__context__, 'sqlite_errorcode', 0) & 255 in (5, 6)
    return isinstance(error, ClientError) and (error.code in {
        'DEADLINE_EXCEEDED', 'TRANSPORT_ERROR', 'INVALID_RESPONSE', 'INVALID_ACK',
        'SERVICE_UNAVAILABLE', 'REQUEST_TIMEOUT', 'RATE_LIMITED', 'SYNC_BUSY', 'SPOOL_BUSY'
    } or (error.status is not None and error.status >= 500
          and error.code not in {'INGEST_DISABLED', 'INGEST_CAPACITY_EXCEEDED'}))


def retire_obsolete_worker(source):
    """Replace a detached old runner too, not just its executable on disk."""
    try:
        previous = private_read(folder('data')/(source+'.worker'))
    except ClientError as error:
        if error.code == 'NOT_LOGGED_IN':
            return
        raise
    if previous.get('version') == VERSION:
        return
    pid = previous.get('pid')
    if type(pid) is not int or pid <= 1 or pid == os.getpid():
        raise ClientError('UPDATE_WORKER_UNVERIFIED')
    # Legacy 0.2.1 records have only a PID. Never signal from that alone: it may
    # have been recycled. ps is available on both supported native platforms.
    result = subprocess.run(['ps', '-ww', '-p', str(pid), '-o', 'uid=', '-o', 'command='],
                            capture_output=True, text=True, timeout=3, check=False)
    if result.returncode == 1 and not result.stdout.strip():
        return  # The recorded worker has already exited.
    fields = result.stdout.strip().split(None, 1)
    command = ([sys.executable] if getattr(sys, 'frozen', False) else
               [sys.executable, '-m', 'chatstone.client.native_runner'])
    prefixes = [' '.join(command+[action, '--source', source, '--worker']) for action in ('sync', 'backfill')]
    if (result.returncode != 0 or len(fields) != 2 or fields[0] != str(os.getuid())
            or not any(fields[1] == prefix or fields[1].startswith(prefix+' ') for prefix in prefixes)):
        return  # Stale/recycled PID: leave its new owner alone and wake normally.
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    end = time.monotonic()+5
    while True:
        try:
            with lease(source+'-worker'):
                return
        except ClientError as error:
            if error.code != 'SYNC_BUSY' or time.monotonic() >= end:
                raise ClientError('UPDATE_WORKER_BUSY') from None
            time.sleep(.1)


def reset_refusals(config):
    """Explicit resume retries conclusive quota denials, never uncertain ACKs."""
    with lease(config['source']), open_spool(config) as spool, spool._transaction():
        rows = spool._db.execute("SELECT batch,payload FROM pending WHERE receipt IN ('rejected','denied') AND code='QUOTA_EXCEEDED'").fetchall()
        for old, payload in rows:
            body = json.loads(payload)
            new = body['batch_id'] = str(uuid4())
            spool._db.execute("UPDATE pending SET batch=?,payload=?,receipt='pending',code=NULL WHERE batch=?",
                (new, json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode(), old))
            for table in ('native_priority', 'native_identity'):
                spool._db.execute('UPDATE '+table+' SET batch=? WHERE batch=?', (new, old))


def run_steps(config, args):
    client = IngestClient(config['origin'], secret_getter=lambda: config['ingest_key'],
                          allow_loopback_http=loopback(), timeout=15)
    count, failures, idle = 0, 0, 0
    until = time.monotonic()+30 if getattr(args, 'worker', False) else 0
    if args.action == 'backfill' and args.retry_skips:
        with lease(args.source), open_spool(config) as spool:
            retry_skipped(spool)
    while True:
        if not config_path(args.source).exists():
            return 0
        try:
            with lease(args.source):
                value = step(config, history=args.action == 'backfill', client=client)
            failures = 0
        except Exception as error:
            if not transient(error):
                raise
            code = cause(error)
            if args.action == 'diagnose':
                value = status(config)
                print(json.dumps(value, sort_keys=True) if args.json else 'Sync probe interrupted ('+code+'); queued messages are safe.')
                if not args.json:
                    print_status(value)
                return 1
            if code in ('SYNC_BUSY', 'SPOOL_BUSY', 'SPOOL_IO:SQLITE_BUSY', 'SPOOL_IO:SQLITE_LOCKED'):
                # Local contention is neither an upload attempt nor a connection failure.
                time.sleep(.05)
                continue
            failures += 1
            if code not in ('SYNC_BUSY', 'SPOOL_BUSY'):
                private_write(folder('data')/(args.source+'.error'), {'cause': code, 'at': int(time.time())})
                if args.action != 'sync' or args.foreground:
                    print(json.dumps({'retrying': code}) if args.json else
                          'Connection interrupted ('+code+'); retrying automatically. Queued messages are safe.', flush=True)
            time.sleep(min(3600, 30*2**min(failures-1, 7)))
            continue
        count += 1
        if args.action != 'sync' or args.foreground:
            print(json.dumps(value, sort_keys=True) if args.json else
                  f"{args.source}: {value['admitted']} found, {value['delivered']} uploaded, "
                  f"{value['pending']} waiting; {sum(value['skips'].values())} skipped.", flush=True)
        if args.action == 'diagnose' or (args.action == 'backfill' and args.steps and count >= args.steps):
            break
        idle = idle+1 if not value['lines'] and not value['pending'] and not value.get('metadata_more') and not value.get('deferred') else 0
        if until:
            try:
                until = max(until, private_read(folder('data')/(args.source+'.hook')).get('at', 0)-time.time()+time.monotonic()+30)
            except ClientError:
                pass
        if idle and (not until or time.monotonic() >= until):
            break
        pause = .5 if idle else .05
        if not value['lines'] and not value['delivered'] and value.get('next_retry'):
            # Poll for newly flushed/live rows while parked uploads sleep; the
            # durable per-item deadline prevents hooks/process restarts bypassing it.
            pause = min(5, max(.05, value['next_retry']-time.time()))
        time.sleep(pause)
    if not args.json and (args.action != 'sync' or args.foreground):
        print(f"Import summary: {value['found']} found, {value['uploaded']} uploaded, {value['pending']} waiting, {sum(value['skips'].values())} skipped.")
        print_status(status(config))
    return 0


def remote_mcp(config):
    """JSON-lines stdio to Streamable HTTP. Auth exists only in this process."""
    headers = {'Authorization': 'Bearer ' + config['read_key'],
               'Accept': 'application/json, text/event-stream'}
    with httpx.Client(timeout=15, trust_env=False, follow_redirects=False) as http:
        def request(value):
            with http.stream('POST', config['origin'] + '/mcp', headers=headers, json=value) as response:
                if response.status_code not in (200, 202):
                    raise ClientError('MCP_REMOTE_REFUSED')
                if response.headers.get('mcp-session-id'):
                    headers['Mcp-Session-Id'] = response.headers['mcp-session-id']
                body = bytearray()
                for block in response.iter_bytes():
                    body.extend(block)
                    if len(body) > 1_048_576:
                        raise ClientError('MCP_RESPONSE_TOO_LARGE')
                    # SSE may keep the stream alive after its JSON-RPC result.
                    normalized = bytes(body).replace(b'\r\n', b'\n')
                    if b'\n\n' in normalized and response.headers.get('content-type', '').startswith('text/event-stream'):
                        for event in normalized.split(b'\n\n')[:-1]:
                            for line in event.decode().splitlines():
                                if line.startswith('data:'):
                                    result = json.loads(line[5:])
                                    if result.get('id') == value.get('id'):
                                        return result
                if not body:
                    return None
                if response.headers.get('content-type', '').startswith('text/event-stream'):
                    raise ClientError('MCP_RESPONSE_INVALID')
                return json.loads(body)
        for raw in iter(lambda: sys.stdin.buffer.readline(262145), b''):
            if len(raw) > 262144:
                raise ClientError('MCP_REQUEST_TOO_LARGE')
            value = json.loads(raw)
            method = value.get('method')
            if method == 'tools/call' and value.get('params', {}).get('name') not in TOOL_NAMES:
                result = {'jsonrpc': '2.0', 'id': value.get('id'),
                          'error': {'code': -32601, 'message': 'READ_TOOL_REQUIRED'}}
            elif method not in ('initialize', 'notifications/initialized', 'ping', 'tools/list', 'tools/call'):
                result = None if 'id' not in value else {'jsonrpc': '2.0', 'id': value['id'],
                           'error': {'code': -32601, 'message': 'METHOD_NOT_FOUND'}}
            else:
                result = request(value)
                if method == 'initialize' and result and 'result' in result:
                    headers['MCP-Protocol-Version'] = result['result']['protocolVersion']
                if method == 'tools/list' and result and 'result' in result:
                    names = [t['name'] for t in result['result']['tools']]
                    if set(names) != set(TOOL_NAMES) or len(names) != 8:
                        raise ClientError('MCP_TOOL_SET_INVALID')
            if result is not None and 'id' in value:
                print(json.dumps(result, separators=(',', ':')), flush=True)


def command_name():
    executable = Path(sys.executable).resolve()
    if getattr(sys, 'frozen', False):
        existing = shutil.which(PRODUCT)
        if existing and Path(existing).resolve() == executable:
            return PRODUCT
        # Only an existing, owner-controlled PATH directory; never profiles,
        # system directories, overwrites or a newly created PATH location.
        for directory in (Path.home()/'.local/bin', Path.home()/'bin'):
            if str(directory) not in os.environ.get('PATH', '').split(os.pathsep):
                continue
            if directory.is_dir() and not directory.is_symlink():
                info = directory.stat()
                link = directory/PRODUCT
                if info.st_uid == os.getuid() and not info.st_mode & 0o022 and not link.exists() and not link.is_symlink():
                    try:
                        link.symlink_to(executable)
                        return PRODUCT
                    except OSError:
                        pass
        return shlex.quote(str(executable))
    return shlex.quote(sys.executable)+' -m chatstone.client.native_runner'


def guidance(code, source):
    command = command_name()
    suffix = ' --source '+source if source else ''
    if code in ('INVALID_KEY', 'INVALID_HOST', 'KEY_SCOPE_CHANGED'):
        return 'Uploads stopped: the key is invalid or revoked ('+code+'); ask the operator for a new code before logging in again.'
    if code in ('QUOTA_EXCEEDED', 'INGEST_CAPACITY_EXCEEDED', 'INGEST_DISABLED'):
        return 'Uploads stopped: the server refused '+code+'; ask the operator to restore capacity or enable uploads, then run '+command+' resume.'
    if code == 'NOT_LOGGED_IN':
        return 'Not logged in; run '+command+' login'+suffix+' with an invitation code from the operator.'
    return 'Chatstone paused ('+code+'); queued messages are safe; run '+command+' diagnose'+suffix+' or contact the operator.'


def stamp(value):
    if not value:
        return 'never'
    from datetime import UTC, datetime
    return datetime.fromtimestamp(value, UTC).isoformat(timespec='seconds')


def hook_stamp(hook):
    return hook.get('event', 'unknown')+' '+stamp(hook['at']) if hook.get('at') else 'never'


def print_status(value):
    if value.get('snapshot_pending'):
        print(value['source']+' '+value['version']+': preparing queue summary; queued messages are safe.')
        return
    success, failure = value.get('last_success', value['upload']), value.get('last_failure', value['error'])
    aside = value.get('set_aside', {})
    print(f"{value['source']} {value['version']}: {value['found']} found, {value['uploaded']} uploaded, "
          f"{value['pending']} waiting; {aside.get('count', 0)} set aside; last hook {hook_stamp(value['hook'])}.")
    print('Last successful upload: '+stamp(success.get('at'))+'; last failed upload: '+
          stamp(failure.get('at'))+(' ('+failure.get('cause', 'unknown')+')' if failure else '')+'.')
    if aside.get('count'):
        labels = {'UPLOAD_BODY_TIMEOUT': 'UPLOAD_BODY_TIMEOUT (too large for this connection)'}
        reasons = ', '.join(labels.get(k, k)+'='+str(n) for k, n in sorted(aside['reasons'].items()))
        print(f"Set aside: {reasons}; largest {aside['largest_bytes']} bytes; "
              f"up to {aside['max_attempts']} attempts; retry automatically after {stamp(value.get('next_retry'))}.")
    if value['skips'] or value['skipped_types']:
        print('Skipped record types: '+(', '.join(k+'='+str(n) for k, n in sorted(value['skipped_types'].items())) or 'none')+
              '; reasons: '+(', '.join(k+'='+str(n) for k, n in sorted(value['skips'].items())) or 'none'))


def main(argv=None):
    parser = argparse.ArgumentParser(prog=PRODUCT)
    parser.add_argument('--version', action='version', version=PRODUCT + ' ' + VERSION)
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('resume', help='Resume existing imports in the background; no new login')
    for name in ('login', 'sync', 'backfill', 'status', 'diagnose', 'mcp', 'logout', 'parse'):
        command = sub.add_parser(name)
        command.add_argument('--source', choices=SOURCES, required=name != 'status')
        command.add_argument('--json', action='store_true', help='Machine-readable output')
        if name in ('sync', 'backfill'):
            command.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
        if name == 'sync':
            command.add_argument('--hook', action='store_true', help=argparse.SUPPRESS)
            command.add_argument('--foreground', action='store_true')
        if name == 'backfill':
            command.add_argument('--steps', type=int, default=0, help='0: run until caught up; Ctrl-C pauses safely')
            command.add_argument('--retry-skips', action='store_true')
        if name == 'parse':
            command.add_argument('path', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == 'resume':
            command = command_name()
            for source in SOURCES:
                if config_path(source).exists():
                    retire_obsolete_worker(source)
                    try:
                        reset_refusals(load(source))
                    except ClientError as error:
                        if error.code not in ('SYNC_BUSY', 'SPOOL_BUSY'):
                            raise
                    wake(source, importing=True)
            print('Configured imports resumed in the background; check '+command+' status.')
            return 0
        if args.action == 'status':
            values = []
            for source in ([args.source] if args.source else SOURCES):
                if not config_path(source).exists() and not args.source:
                    if not args.json:
                        try:
                            hook = private_read(folder('data')/(source+'.hook'))
                        except ClientError:
                            hook = {}
                        print(source+': not logged in; last hook '+hook_stamp(hook)+'.')
                    continue
                while True:
                    try:
                        value = status(load(source))
                        break
                    except ClientError as error:
                        if error.code not in ('SYNC_BUSY', 'SPOOL_BUSY'):
                            raise
                        time.sleep(.1)
                values.append(value)
                if not args.json:
                    print_status(value)
            if args.json:
                print(json.dumps(values[0] if args.source else values, sort_keys=True))
            return 0
        if args.action == 'parse':
            # Synthetic fixture only, no key or persistent user state needed.
            with tempfile.TemporaryDirectory() as temporary, Spool(
                    Path(temporary).resolve()/'queue', source=args.source, host='synthetic', destination=ORIGIN) as spool:
                print(json.dumps(capture(spool, None, paths=[args.path.resolve()], max_lines=2048)))
            return 0
        if args.action == 'login':
            with lease(args.source):
                login(args.source)
            return 0
        if args.action == 'sync' and not (args.worker or args.foreground):
            wake(args.source, hook=args.hook)
            return 0
        config = load(args.source)
        if args.action == 'mcp':
            remote_mcp(config)
            return 0
        if args.action in ('sync', 'diagnose', 'backfill'):
            if getattr(args, 'worker', False):
                try:
                    with lease(args.source+'-worker'):
                        private_write(folder('data')/(args.source+'.worker'), {'pid': os.getpid(), 'version': VERSION})
                        return run_steps(config, args)
                except ClientError as error:
                    if error.code == 'SYNC_BUSY':
                        return 0
                    raise
            return run_steps(config, args)
        with lease(args.source):
            if args.action == 'logout':
                config_path(args.source).unlink()
                print('Local keys removed; queued records and remote archive retained. Ask operator to revoke keys.')
            elif args.action == 'status':
                print(json.dumps(status(config), sort_keys=True))
        return 0
    except KeyboardInterrupt:
        print('{"cause":"PAUSED_SAFE_TO_RESUME"}' if getattr(args, 'json', False) else 'Paused safely; '+command_name()+' resume continues in the background.', file=sys.stderr)
        return 130
    except Exception as error:  # noqa: BLE001 -- never expose private values/paths
        code = cause(error)
        if code == 'SYNC_BUSY' and args.action == 'sync':
            return 0
        if args.action not in ('parse', 'resume') and args.source:
            private_write(folder('data') / (args.source + '.error'), {'cause': code, 'at': int(time.time())})
        print(json.dumps({'cause': code}) if getattr(args, 'json', False) else guidance(code, getattr(args, 'source', None)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
