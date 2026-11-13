"""SQLite FULL-sync spool; at-least-once transport, stable batch identity.

One record per batch keeps retries and wire limits explicit. A seen fingerprint
and its pending payload commit atomically. Only a validated positive final receipt
removes the payload. Queue admission is not success. Final negative receipts keep
the record and permit one new stable attempt on a later flush. Strict FIFO blocks
newer revisions until their predecessor is applied; uncertain ACKs never rotate IDs.
No pruning of unacknowledged records or identity tombstones occurs.
Only use a trusted directory owned by the current OS user: SQLite opens by path,
so this is not protection from a malicious same-UID concurrent rename.
"""
import fcntl
import hashlib
import json
import os
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path
from time import monotonic
from uuid import uuid4

from .ingest import encode_ingest_json, encode_record, encode_spool_json, identity
from .transport import ClientError

# Optional feature version; the legacy delivery schema/identity stays at v2.
_EPOCH_SCHEMA = (
    'CREATE TABLE epoch_format (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL)',
    ('CREATE TABLE epoch_state (id INTEGER PRIMARY KEY CHECK(id=1), epoch TEXT NOT NULL, '
     'binding BLOB NOT NULL, total INTEGER NOT NULL, ordinal INTEGER NOT NULL, blocked TEXT, '
     'proof TEXT NOT NULL)'),
    ('CREATE TABLE epoch_sequences (session TEXT PRIMARY KEY, count INTEGER NOT NULL, '
     'proof TEXT NOT NULL)'),
)
_EPOCH_STOP_INDEX = ("CREATE INDEX epoch_pending_stop ON pending(seq) WHERE code IS NOT NULL "
                     "OR receipt IN ('rejected','denied')")


class Spool:
    def __init__(self, path, *, source, host, destination, max_bytes=67108864, max_pending=1000,
                 existing_only=False, expected_install=None):
        if (type(max_bytes) is not int or not 262144 <= max_bytes <= 1073741824
                or type(max_pending) is not int or not 1 <= max_pending <= 10000):
            raise ClientError('INVALID_SPOOL_LIMIT')
        self.path = Path(path).absolute()
        self.source, self.host, self.destination = source, host, destination.rstrip('/')
        self.max_pending = max_pending
        if type(existing_only) is not bool or (existing_only and expected_install is None):
            raise ClientError('INVALID_REQUEST')
        self.existing_only = existing_only or expected_install is not None
        self.expected_install = identity(expected_install) if expected_install is not None else None
        self._db = self._lock = self._dir = None
        self._registration = None
        try:
            self._open(max_bytes)
        except BaseException:
            self.close()
            raise

    def _open(self, max_bytes):
        try:
            for ancestor in (*reversed(self.path.parents), self.path):
                if ancestor.is_symlink():
                    raise ClientError('SPOOL_UNSAFE')
            if not self.existing_only:
                self.path.mkdir(mode=0o700, exist_ok=True)
            info = self.path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ClientError('SPOOL_UNSAFE')
            self._dir = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            for item in self.path.iterdir():
                if item.name not in ('.lock', 'spool.sqlite3', 'spool.sqlite3-journal'):
                    raise ClientError('SPOOL_UNSAFE')
                self._check_file(item.lstat())
            create = 0 if self.existing_only else os.O_CREAT
            self._lock = os.open('.lock', os.O_RDWR | create | os.O_NOFOLLOW,
                                 0o600, dir_fd=self._dir)
            self._check_file(os.fstat(self._lock))
            try:
                fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ClientError('SPOOL_BUSY') from None
            fd = os.open('spool.sqlite3', os.O_RDWR | create | os.O_NOFOLLOW,
                         0o600, dir_fd=self._dir)
            try:
                self._check_file(os.fstat(fd))
            finally:
                os.close(fd)
            if self.existing_only:
                # Inspect under the lock without journal recovery or any writes.
                # The subsequent ordinary reopen may recover a hot data transaction;
                # automatic mode never creates or migrates an identity.
                probe = sqlite3.connect((self.path / 'spool.sqlite3').as_uri()
                                        + '?mode=ro&immutable=1', uri=True)
                try:
                    row = probe.execute('SELECT install,source,host,destination,version '
                                        'FROM identity WHERE id=1').fetchone()
                    if row != (self.expected_install, self.source, self.host, self.destination, 2):
                        raise ClientError('SPOOL_IDENTITY_MISMATCH')
                finally:
                    probe.close()
                self.install_id = row[0]
            os.fsync(self._dir)
            self._db = sqlite3.connect(self.path / 'spool.sqlite3', timeout=0, isolation_level=None)
            self._db.execute('PRAGMA trusted_schema=OFF')
            self._db.execute('PRAGMA journal_mode=DELETE')
            self._db.execute('PRAGMA synchronous=FULL')
            self._db.execute('PRAGMA temp_store=MEMORY')
            # Reserve >2x DB space for rollback journal pages/headers and metadata.
            pages = (max_bytes - 8192) // (3 * 4096)
            if self._db.execute('PRAGMA page_size').fetchone()[0] != 4096:
                raise ClientError('SPOOL_CORRUPT')
            if self._db.execute('PRAGMA page_count').fetchone()[0] > pages:
                raise ClientError('SPOOL_FULL')
            self._db.execute(f'PRAGMA max_page_count={pages}')
            if self._db.execute('PRAGMA quick_check').fetchone() != ('ok',):
                raise ClientError('SPOOL_CORRUPT')
            if self.existing_only:
                return
            with self._transaction():
                self._db.execute('CREATE TABLE IF NOT EXISTS identity '
                                 '(id INTEGER PRIMARY KEY CHECK(id=1), install TEXT, '
                                 'source TEXT, host TEXT, destination TEXT, version INTEGER)')
                self._db.execute('CREATE TABLE IF NOT EXISTS seen '
                                 '(native TEXT PRIMARY KEY, fingerprint TEXT NOT NULL)')
                self._db.execute('CREATE TABLE IF NOT EXISTS pending '
                                 '(seq INTEGER PRIMARY KEY AUTOINCREMENT, batch TEXT UNIQUE, '
                                 "payload BLOB NOT NULL, receipt TEXT NOT NULL DEFAULT 'pending', code TEXT)")
                self._db.execute('INSERT OR IGNORE INTO identity VALUES (1,?,?,?,?,2)',
                                 (str(uuid4()), self.source, self.host, self.destination))
                row = self._db.execute('SELECT install,source,host,destination,version '
                                       'FROM identity WHERE id=1').fetchone()
                if row[1:4] != (self.source, self.host, self.destination) or row[4] not in (1, 2):
                    raise ClientError('SPOOL_IDENTITY_MISMATCH')
                if row[4] == 1:
                    # Old queue-ACK deletion left no trustworthy final receipt.
                    # Never certify (or erase) those seen-only identities. A legacy
                    # spool can upgrade only while every checkpoint is recoverable.
                    recoverable = {}
                    try:
                        for (payload,) in self._db.execute('SELECT payload FROM pending ORDER BY seq'):
                            value = json.loads(payload)['records'][0]
                            message = value['message']
                            native = json.dumps([message['native_session_id'], message['native_id']],
                                                separators=(',', ':'))
                            recoverable[native] = hashlib.sha256(encode_ingest_json(value)).hexdigest()
                    except (KeyError, IndexError, TypeError, ValueError):
                        raise ClientError('SPOOL_CORRUPT') from None
                    if any(recoverable.get(native) != fingerprint for native, fingerprint in
                           self._db.execute('SELECT native,fingerprint FROM seen')):
                        raise ClientError('SPOOL_LEGACY_RECEIPTS')
                    self._db.execute("ALTER TABLE pending ADD COLUMN receipt TEXT NOT NULL DEFAULT 'pending'")
                    self._db.execute('ALTER TABLE pending ADD COLUMN code TEXT')
                    self._db.execute('UPDATE identity SET version=2 WHERE id=1')
                self.install_id = row[0]
            os.fsync(self._dir)
        except FileNotFoundError:
            raise ClientError('SPOOL_MISSING' if self.existing_only else 'SPOOL_UNSAFE') from None
        except OSError:
            raise ClientError('SPOOL_UNSAFE') from None
        except sqlite3.Error:
            raise ClientError('SPOOL_CORRUPT') from None

    @staticmethod
    def _check_file(info):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ClientError('SPOOL_UNSAFE')

    @contextmanager
    def _transaction(self):
        try:
            self._db.execute('BEGIN IMMEDIATE')
            yield
            self._db.commit()
        except BaseException as error:
            self._db.rollback()
            if isinstance(error, sqlite3.Error):
                code = 'SPOOL_FULL' if error.sqlite_errorcode == sqlite3.SQLITE_FULL else 'SPOOL_IO'
                raise ClientError(code) from None
            raise

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        self._registration = None
        if self._db is not None:
            self._db.close()
            self._db = None
        for name in ('_lock', '_dir'):
            fd = getattr(self, name)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

    def _epoch_schema(self):
        return dict(self._db.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='table' AND name LIKE 'epoch_%'"))

    def _epoch_ready(self):
        schema = self._epoch_schema()
        if not schema:
            raise ClientError('EPOCH_NOT_PREPARED')
        if (schema != {sql.split()[2]: sql for sql in _EPOCH_SCHEMA}
                or self._db.execute('SELECT * FROM epoch_format').fetchall() != [(1, 1)]):
            raise ClientError('SPOOL_CORRUPT')
        if self._db.execute('SELECT install,source,host,destination,version FROM identity '
                            'WHERE id=1').fetchone() != (
                                self.install_id, self.source, self.host, self.destination, 2):
            raise ClientError('SPOOL_IDENTITY_MISMATCH')

    def prepare_epochs(self):
        """Explicit, atomic feature-v1 preparation; never changes install/v2 data.

        No open/add/flush path calls this. Added pages and their rollback journal
        share the existing spool budget. A partial/unknown feature is refused,
        not repaired. Old clients ignore these tables: do not mix replay routes.
        """
        assert self._db is not None
        with self._transaction():
            if not self._epoch_schema():
                for sql in _EPOCH_SCHEMA:
                    self._db.execute(sql)
                self._db.execute('INSERT INTO epoch_format VALUES (1,1)')
            self._epoch_read()
            index = self._db.execute("SELECT sql FROM sqlite_master WHERE type='index' "
                                     "AND name='epoch_pending_stop'").fetchone()
            if index is None:
                self._db.execute(_EPOCH_STOP_INDEX)
            elif index != (_EPOCH_STOP_INDEX,):
                raise ClientError('SPOOL_CORRUPT')

    @staticmethod
    def _epoch_proof(epoch, binding, total, ordinal, blocked):
        metadata = json.dumps([epoch, total, ordinal, blocked], separators=(',', ':')).encode()
        return hashlib.sha256(binding + b'\x00' + metadata).hexdigest()

    @staticmethod
    def _sequence_proof(key, count):
        return hashlib.sha256(key.encode() + b'\x00' + str(count).encode()).hexdigest()

    def _epoch_binding(self, binding):
        if (type(binding) is not dict or set(binding) != {
                'source_path', 'source_device', 'source_inode', 'seal'}
                or type(binding['source_path']) is not str
                or not binding['source_path'].startswith('/') or '\x00' in binding['source_path']
                or any(type(binding[key]) is not int or not 0 <= binding[key] < 2**63
                       for key in ('source_device', 'source_inode'))
                or type(binding['seal']) is not str or len(binding['seal']) != 64
                or any(c not in '0123456789abcdef' for c in binding['seal'])):
            raise ClientError('INVALID_REQUEST')
        # seal is the caller's digest of the complete validated frozen descriptor,
        # not a certificate minted by this spool. No source paths are opened here.
        return encode_ingest_json({'install': self.install_id, 'source': self.source,
                                   'host': self.host, 'destination': self.destination,
                                   **{key: binding[key] for key in sorted(binding)}})

    def _epoch_read(self):
        self._epoch_ready()
        rows = self._db.execute(
            'SELECT epoch,binding,total,ordinal,blocked,proof FROM epoch_state').fetchall()
        if len(rows) > 1:
            raise ClientError('SPOOL_CORRUPT')
        if not rows:
            if self._db.execute('SELECT 1 FROM epoch_sequences LIMIT 1').fetchone():
                raise ClientError('SPOOL_CORRUPT')
            return None
        epoch, binding, total, ordinal, blocked, proof = rows[0]
        try:
            identity(epoch)
            stored = json.loads(binding)
            if type(binding) is not bytes or type(stored) is not dict:
                raise ValueError
            descriptor = {key: stored.pop(key) for key in (
                'source_path', 'source_device', 'source_inode', 'seal')}
            if self._epoch_binding(descriptor) != binding:
                raise ValueError
        except (ClientError, KeyError, TypeError, ValueError):
            raise ClientError('SPOOL_CORRUPT') from None
        if (type(total) is not int or type(ordinal) is not int or not 0 <= ordinal <= total
                or blocked not in (None, 'REQUEST_TOO_LARGE')
                or (blocked is not None and ordinal == total)
                or proof != self._epoch_proof(epoch, binding, total, ordinal, blocked)):
            raise ClientError('SPOOL_CORRUPT')
        # Stream counters, never load/rewrite the full session map. Digests detect
        # accidental valid-looking damage, not a malicious same-UID rewrite.
        counted = 0
        for key, count, proof in self._db.execute('SELECT session,count,proof FROM epoch_sequences'):
            if (type(key) is not str or type(count) is not int or not 1 <= count <= ordinal
                    or proof != self._sequence_proof(key, count)):
                raise ClientError('SPOOL_CORRUPT')
            counted += count
        if counted != ordinal:
            raise ClientError('SPOOL_CORRUPT')
        return rows[0][:5]

    def _epoch_match(self, epoch_id, binding):
        identity(epoch_id)
        expected = self._epoch_binding(binding)
        row = self._epoch_read()
        if row is None or row[:2] != (epoch_id, expected):
            raise ClientError('EPOCH_BINDING_MISMATCH')
        return row

    def _epoch_guard(self):
        if self._db.execute("SELECT 1 FROM pending WHERE code IS NOT NULL "
                            "OR receipt IN ('rejected','denied') LIMIT 1").fetchone():
            raise ClientError('SPOOL_REJECTED')

    def begin_epoch(self, epoch_id, *, binding, total):
        """Begin/idempotently reopen one SEALED replay; never seal or read a source.

        The caller must revalidate its protected sealed files, live-source inode
        and credentials before every call. A new epoch cannot replace unresolved
        admission or pending delivery. Completion here means local admission only.
        """
        identity(epoch_id)
        expected = self._epoch_binding(binding)
        if type(total) is not int or not 0 <= total < 2**63:
            raise ClientError('INVALID_REQUEST')
        row = self._epoch_read()
        self._epoch_guard()
        if row is not None:
            if row[0] == epoch_id:
                if row[1:3] != (expected, total):
                    raise ClientError('EPOCH_BINDING_MISMATCH')
                return self.epoch_status(epoch_id, binding=binding)
            if row[2] != row[3] or self._db.execute('SELECT 1 FROM pending LIMIT 1').fetchone():
                raise ClientError('EPOCH_UNRESOLVED')
        with self._transaction():
            self._db.execute('DELETE FROM epoch_sequences')
            self._db.execute('DELETE FROM epoch_state')
            self._db.execute('INSERT INTO epoch_state VALUES (1,?,?,?,0,NULL,?)',
                             (epoch_id, expected, total,
                              self._epoch_proof(epoch_id, expected, total, 0, None)))
        return self.epoch_status(epoch_id, binding=binding)

    def epoch_status(self, epoch_id, *, binding):
        """Content-free durable admission state, NOT a final delivery receipt."""
        _, _, total, ordinal, blocked = self._epoch_match(epoch_id, binding)
        return {'epoch_id': epoch_id, 'total': total, 'next_ordinal': ordinal,
                'state': 'blocked' if blocked else ('complete' if ordinal == total else 'admitting'),
                'blocked': {'ordinal': ordinal, 'code': blocked} if blocked else None,
                'complete': ordinal == total}

    @staticmethod
    def _session_key(session):
        """SQLite scalars, with Python dict equality (not SQL affinity/JSON keys).

        int/float equality is exact rational equality, including signed zero and
        large integers. NULL, TEXT and BLOB are separate domains. Nonfinite floats
        cannot occur in a successfully validated sealed source and are refused.
        """
        if session is None:
            value = ['null']
        elif type(session) in (int, float):
            try:
                numerator, denominator = session.as_integer_ratio()
            except (OverflowError, ValueError):
                raise ClientError('INVALID_REQUEST') from None
            value = ['number', str(numerator), str(denominator)]
        elif type(session) is str:
            value = ['text', session]
        elif type(session) is bytes:
            value = ['blob', session.hex()]
        else:
            raise ClientError('INVALID_REQUEST')
        return json.dumps(value, ensure_ascii=True, separators=(',', ':'))

    def _epoch_sequence(self, key):
        row = self._db.execute('SELECT count FROM epoch_sequences WHERE session=?', (key,)).fetchone()
        return row[0] if row else 0

    def admit_epoch(self, epoch_id, *, binding, start, rows, normalize):
        """Commit a sealed replay slice, its ordinal AND exact session counters.

        rows yields (original session scalar, raw value); normalize(raw, seq)
        returns the unchanged ParsedRecord. It must have no spool/network side
        effects. The caller owns/retains SEALED originals and validates the seal
        and current source/credential binding, budgets and file extents. Resume
        ONLY from epoch_status.next_ordinal, never from lost return counters.

        Groups retain <=100 envelopes / <=1 MiB (or one permitted2MiB envelope),
        plus one lookahead. Any refused
        row stays at the watermark. Wire oversize becomes a sticky blocked state,
        not a skip; its original remains outside this primitive for explicit
        recovery. No deletion/retirement or automatic retry of a blocked epoch.
        Result counters describe this call only; complete means local admission,
        never final delivery. Exceptions may follow earlier committed groups.
        """
        _, expected, total, ordinal, blocked = self._epoch_match(epoch_id, binding)
        self._epoch_guard()
        if type(start) is not int or start != ordinal:
            raise ClientError('EPOCH_POSITION_MISMATCH')
        counts = {'processed': 0, 'queued': 0, 'unchanged': 0, 'error': blocked}

        def result():
            return {**counts, **self.epoch_status(epoch_id, binding=binding)}

        if blocked:
            return result()

        def apply(item):
            prepared, key, seq, position = item
            current = self._db.execute('SELECT epoch,binding,ordinal,blocked FROM epoch_state '
                                       'WHERE id=1').fetchone()
            if current != (epoch_id, expected, position, None):
                raise ClientError('EPOCH_POSITION_MISMATCH')
            if self._epoch_sequence(key) != seq:
                raise ClientError('EPOCH_SEQUENCE_MISMATCH')
            batch = self._add_prepared(prepared)
            self._db.execute('INSERT INTO epoch_sequences VALUES (?,?,?) ON CONFLICT(session) '
                             'DO UPDATE SET count=excluded.count,proof=excluded.proof',
                             (key, seq + 1, self._sequence_proof(key, seq + 1)))
            self._db.execute('UPDATE epoch_state SET ordinal=?,proof=? WHERE id=1',
                             (position + 1, self._epoch_proof(
                                 epoch_id, expected, total, position + 1, None)))
            return batch

        def commit(group):
            outcomes = self._add_group(group, apply=apply, guard=self._epoch_guard)
            for batch, error in outcomes:
                if error:
                    counts['error'] = error
                    return False
                counts['processed'] += 1
                counts['queued' if batch else 'unchanged'] += 1
            return True

        group, size, sequences = [], 0, {}
        for session, raw in rows:
            if ordinal >= total:
                raise ClientError('EPOCH_POSITION_MISMATCH')
            key = self._session_key(session)
            seq = sequences[key] if key in sequences else self._epoch_sequence(key)
            try:
                record = normalize(raw, seq)
                if (type(record.message.seq) is not int or record.message.seq != seq
                        or self._session_key(record.message.native_session_id) != key):
                    raise ClientError('EPOCH_SEQUENCE_MISMATCH')
                prepared = self._prepare(record)
            except ClientError as error:
                if error.code != 'REQUEST_TOO_LARGE':
                    raise
                prepared = None
            if group and (prepared is None or len(group) == 100
                          or size + len(prepared[3]) > 1048576):
                if not commit(group):
                    return result()
                group, size, sequences = [], 0, {}
            if prepared is None:
                try:
                    with self._transaction():
                        self._epoch_guard()
                        changed = self._db.execute(
                            "UPDATE epoch_state SET blocked='REQUEST_TOO_LARGE',proof=? WHERE id=1 "
                            'AND epoch=? AND binding=? AND ordinal=? AND blocked IS NULL',
                            (self._epoch_proof(epoch_id, expected, total, ordinal, 'REQUEST_TOO_LARGE'),
                             epoch_id, expected, ordinal)).rowcount
                        if changed != 1:
                            raise ClientError('EPOCH_POSITION_MISMATCH')
                except ClientError as error:
                    if error.code != 'SPOOL_FULL':
                        raise
                    counts['error'] = error.code
                else:
                    counts['error'] = 'REQUEST_TOO_LARGE'
                return result()
            group.append((prepared, key, seq, ordinal))
            size += len(prepared[3])
            sequences[key] = seq + 1
            ordinal += 1
        if group:
            commit(group)
        return result()

    def _prepare(self, record):
        message = record.message
        if (message.source, message.host_id) != (self.source, self.host):
            raise ClientError('SPOOL_IDENTITY_MISMATCH')
        value = encode_record(record)
        fingerprint = hashlib.sha256(encode_spool_json(value)).hexdigest()
        native = json.dumps([message.native_session_id, message.native_id], separators=(',', ':'))
        batch = str(uuid4())
        body = encode_spool_json({'install_id': self.install_id, 'batch_id': batch, 'records': [value]})
        return native, fingerprint, batch, body

    def _add_prepared(self, prepared):
        native, fingerprint, batch, body = prepared
        previous = self._db.execute('SELECT fingerprint FROM seen WHERE native=?',
                                    (native,)).fetchone()
        if previous == (fingerprint,):
            return None
        if self._db.execute('SELECT count(*) FROM pending').fetchone()[0] >= self.max_pending:
            raise ClientError('SPOOL_FULL')
        self._db.execute('INSERT INTO pending(batch,payload) VALUES (?,?)', (batch, body))
        if self._db.execute("SELECT 1 FROM sqlite_master WHERE name='hermes_fresh'").fetchone():
            fence = self._db.execute('SELECT fence FROM hermes_fresh WHERE id=1').fetchone()[0]
            native_id = json.loads(native)[1]
            if isinstance(native_id, str) and native_id.isdecimal() and int(native_id) > fence:
                self._db.execute('UPDATE pending SET fresh=0 WHERE batch=?', (batch,))
        self._db.execute('INSERT INTO seen VALUES (?,?) ON CONFLICT(native) DO UPDATE '
                         'SET fingerprint=excluded.fingerprint', (native, fingerprint))
        return batch

    def add(self, record):
        prepared = self._prepare(record)
        with self._transaction():
            batch = self._add_prepared(prepared)
        return batch

    def _add_group(self, group, *, apply=None, guard=None):
        apply = self._add_prepared if apply is None else apply
        try:
            with self._transaction():
                # Check after BEGIN IMMEDIATE and before any effect. No user
                # callbacks run within this transaction, and its writer lock
                # excludes concurrent receipt changes; scanning per row repeats
                # the same guard over a growing payload-bearing queue.
                if guard is not None:
                    guard()
                outcomes = [(apply(item), None) for item in group]
            return outcomes
        except ClientError as error:
            if error.code != 'SPOOL_FULL':
                raise
        # SQLITE_FULL may roll back the ENTIRE transaction, not just its last
        # statement. No outcome has escaped. Replay this bounded group alone as
        # singles to commit the valid prefix, retaining the prepared IDs/bytes.
        outcomes = []
        for item in group:
            try:
                with self._transaction():
                    if guard is not None:
                        guard()
                    batch = apply(item)
            except ClientError as error:
                if error.code != 'SPOOL_FULL':
                    raise
                outcomes.append((None, error.code))
                break
            outcomes.append((batch, None))
        return outcomes

    def add_many(self, records):
        """Yield (batch-or-None, error-code-or-None) in input order after commit.

        Local groups hold <=100 envelopes and <=1 MiB encoded payload, plus at
        most one prepared lookahead envelope. Original records are not buffered.
        REQUEST_TOO_LARGE is visible and skipped without a checkpoint. SPOOL_FULL
        commits/reports only the valid prefix and stops; later records must be
        rescanned. Other exceptions/cancellation discard the unfinished group,
        never previously committed groups. Closing early may leave committed but
        unreported outcomes; replay is safe. No network or receipt work occurs.
        """
        group, size = [], 0
        for record in records:
            try:
                prepared = self._prepare(record)
            except ClientError as error:
                if error.code != 'REQUEST_TOO_LARGE':
                    raise
                prepared = None
            if group and (prepared is None or len(group) == 100
                          or size + len(prepared[3]) > 1048576):
                outcomes = self._add_group(group)
                yield from outcomes
                if outcomes[-1][1] == 'SPOOL_FULL':
                    return
                group, size = [], 0
            if prepared is None:
                yield None, 'REQUEST_TOO_LARGE'
            else:
                group.append(prepared)
                size += len(prepared[3])
        if group:
            yield from self._add_group(group)

    def pending(self):
        return [json.loads(row[0]) for row in self._db.execute('SELECT payload FROM pending ORDER BY seq')]

    def status(self):
        """Content-free durable recovery state, including admission-only denials."""
        pending, rejected, retryable = self._db.execute(
            "SELECT count(*),count(code),count(*) FILTER (WHERE receipt='rejected') FROM pending"
        ).fetchone()
        errors = dict(self._db.execute(
            'SELECT code,count(*) FROM pending WHERE code IS NOT NULL GROUP BY code'))
        return {'pending': pending, 'rejected': rejected, 'retryable': retryable, 'errors': errors}

    @staticmethod
    def _receipt(result, batch):
        """Validate the single-record contract before any durable state transition."""
        state, results = result.get('state'), result.get('results')
        if (state not in ('queued', 'done') or result.get('batch_id') != batch
                or result.get('admission') not in (None, 'denied')):
            raise ClientError('INVALID_ACK')
        if results is None and state == 'queued' and result.get('admission') is None:
            return 'queued', None
        if (not isinstance(results, list) or len(results) != 1
                or not isinstance(results[0], dict)):
            raise ClientError('INVALID_ACK')
        verdict = results[0]
        status = verdict.get('status')
        if not isinstance(status, str):
            raise ClientError('INVALID_ACK')
        if status == 'inserted' and result.get('admission') == 'denied':
            raise ClientError('INVALID_ACK')
        if status in ('inserted', 'unchanged'):
            if (type(verdict.get('message_id')) is not int or verdict['message_id'] < 1
                    or type(verdict.get('revision')) is not int or verdict['revision'] < 1
                    or verdict.get('code') is not None):
                raise ClientError('INVALID_ACK')
            return ('applied' if state == 'done' else 'queued'), None
        code = {'quota_exceeded': 'QUOTA_EXCEEDED', 'invalid': 'INVALID_RECORD'}.get(status)
        if code is None or verdict.get('code') != code:
            raise ClientError('INVALID_ACK')
        return ('rejected' if state == 'done' else 'denied'), code

    def _delivery_rows(self, limit):
        fresh = self._db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                                 "AND name='hermes_fresh'").fetchone()
        order = 'fresh,seq' if fresh else 'seq'
        return self._db.execute(
            f'SELECT batch,payload,receipt FROM pending ORDER BY {order} LIMIT ?', (limit,))

    def _flush_ordered(self, client, deadline):
        """Group unchanged durable envelopes, never records or queue identities."""
        batches = []
        for batch, payload, receipt in self._delivery_rows(8):
            if receipt == 'rejected':
                break
            body = json.loads(payload)
            if body.get('batch_id') != batch:
                raise ClientError('INVALID_ACK')
            candidate = batches + [body]
            try:
                encode_ingest_json({'batches': candidate})
            except ClientError as error:
                if error.code != 'REQUEST_TOO_LARGE':
                    raise
                break
            batches = candidate
        if len(batches) < 2:
            return None  # A large head uses the unchanged full-size single endpoint.
        try:
            result = client.enqueue_ordered(batches=batches, deadline=deadline)
        except ClientError as error:
            if error.code == 'REQUEST_TOO_LARGE':
                return None  # NUL conversion can enlarge the complete wrapper.
            raise
        receipts = result.get('receipts') if isinstance(result, dict) else None
        if not isinstance(receipts, list) or not 1 <= len(receipts) <= len(batches):
            raise ClientError('INVALID_ACK')
        checked = []
        for index, result in enumerate(receipts):
            if not isinstance(result, dict):
                raise ClientError('INVALID_ACK')
            receipt, code = self._receipt(result, batches[index]['batch_id'])
            if receipt != 'applied' and index != len(receipts) - 1:
                raise ClientError('INVALID_ACK')
            checked.append((batches[index]['batch_id'], receipt, code))
        with self._transaction():
            for batch, receipt, code in checked:
                if receipt == 'applied':
                    self._db.execute('DELETE FROM pending WHERE batch=?', (batch,))
                else:
                    self._db.execute('UPDATE pending SET receipt=?,code=? WHERE batch=?',
                                     (receipt, code, batch))
        return sum(receipt == 'applied' for _, receipt, _ in checked), checked[-1][1] != 'applied'

    def flush(self, client):
        """Final-receipt FIFO delivery under one shared deadline.

        The explicit ordered endpoint may carry a bounded prefix of original
        one-record envelopes. It cannot overtake a queued or negative head.
        Replaying enqueue is the existing idempotent receipt lookup. Stop on the
        first non-final/negative receipt, never poll or overtake it. A subsequent
        explicit flush retries a conclusively rejected attempt with a fresh ID,
        persisted in the same FIFO slot BEFORE sending. Lost ACKs replay that ID.
        """
        previous, self._registration = self._registration, None
        if client.base_url != self.destination:
            raise ClientError('SPOOL_IDENTITY_MISMATCH')
        deadline = monotonic() + client.timeout
        registration = (client, client.base_url, self.install_id, self.source, self.host)
        # One open-spool/client setup marker, not permission. Every enqueue still
        # authenticates at the server. Empty flushes retain their network check;
        # any failed flush leaves no marker, and reopening never restores one.
        if (previous is None or previous[0] is not client or previous[1:] != registration[1:]
                or not self._db.execute('SELECT 1 FROM pending LIMIT 1').fetchone()):
            client.register_source(install_id=self.install_id, source=self.source, host=self.host,
                                   deadline=deadline)
        count = 0
        while row := self._delivery_rows(1).fetchone():
            if monotonic() >= deadline:
                raise ClientError('DEADLINE_EXCEEDED')
            batch, payload, previous = row
            if getattr(client, 'ordered', False) and previous != 'rejected':
                grouped = self._flush_ordered(client, deadline)
                if grouped is not None:
                    applied, stopped = grouped
                    count += applied
                    if stopped or monotonic() + client.timeout / 2 >= deadline:
                        break
                    continue
            body = json.loads(payload)
            if previous == 'rejected':
                batch = body['batch_id'] = str(uuid4())
                payload = encode_spool_json(body)
                with self._transaction():
                    self._db.execute("UPDATE pending SET batch=?,payload=?,receipt='pending',code=NULL "
                                     'WHERE batch=?', (batch, payload, row[0]))
            result = client.enqueue(**body, deadline=deadline)
            receipt, code = self._receipt(result, batch)
            with self._transaction():
                if receipt == 'applied':
                    self._db.execute('DELETE FROM pending WHERE batch=?', (batch,))
                else:
                    self._db.execute('UPDATE pending SET receipt=?,code=? WHERE batch=?',
                                     (receipt, code, batch))
            if receipt != 'applied':
                break
            count += 1
            # Continuous final receipts are normal, not a timed-out flush.
            # Yield with room for the next request rather than start it at the
            # end of this shared budget. All unsent tail bytes/IDs stay intact.
            if monotonic() + min(2.0, client.timeout / 2) >= deadline:
                break
        self._registration = registration
        return count
