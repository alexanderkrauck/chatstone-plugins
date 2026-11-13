"""Bounded native hook runner. No harness config contains credentials."""
from __future__ import annotations

import argparse
import fcntl
import getpass
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import warnings
from contextlib import contextmanager
from pathlib import Path

import httpx

from .harness_capture import capture, discover, prepare, retry_skipped
from .ingest import IngestClient
from .native_product import ORIGIN, PRODUCT, VERSION
from .spool import Spool
from .transport import TOKEN, TOOL_NAMES, Client, ClientError

SOURCES = ('claude_code', 'codex')


class NativeSpool(Spool):
    """Only scheduling differs; persistence, retries and upload are shared."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.live = False
        with self._transaction():
            self._db.execute('CREATE TABLE IF NOT EXISTS native_priority(batch TEXT PRIMARY KEY, priority INTEGER)')
            self._db.execute('DELETE FROM native_priority WHERE batch NOT IN (SELECT batch FROM pending)')

    def _add_prepared(self, prepared):
        batch = super()._add_prepared(prepared)
        if batch:
            self._db.execute('INSERT INTO native_priority VALUES(?,?)', (batch, 0 if self.live else 1))
        return batch

    def _delivery_rows(self, limit):
        return self._db.execute('SELECT p.batch,p.payload,p.receipt FROM pending p '
            'LEFT JOIN native_priority n ON p.batch=n.batch '
            'ORDER BY coalesce(n.priority,1),p.seq LIMIT ?', (limit,))


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
    print('Login complete. Run ' + PRODUCT + ' backfill --source ' + source)


def step(config, *, history=False, lines=256):
    with open_spool(config) as spool:
        prepare(spool)
        # Keep file scheduling outside the proven atomic per-record reader.
        files = [p for root in config['roots'] if Path(root).is_dir()
                 for p in discover(root, config['source'])]
        files.sort(key=lambda p: p.stat().st_mtime_ns, reverse=True)
        known = {r[0]: r[1] for r in spool._db.execute('SELECT identity,size FROM harness_files')}
        live, old = [], []
        for path in files:
            info = path.stat()
            key = f'{info.st_dev}:{info.st_ino}'
            # Completed files with fresh bytes overtake interrupted history.
            (live if key in known and known[key] >= 0 and known[key] != info.st_size else old).append(path)
        total = {'admitted': 0, 'skipped': 0, 'lines': 0}
        for group in (live, old):
            spool.live = group is live
            if total['lines'] >= lines:
                break
            result = capture(spool, None, paths=group, attachment_roots=config.get('attachment_roots', ()),
                             max_lines=lines-total['lines'])
            for key in total:
                total[key] += result[key]
        client = IngestClient(config['origin'], secret_getter=lambda: config['ingest_key'],
                              allow_loopback_http=loopback(), timeout=4)
        client.ordered = True
        total['delivered'] = spool.flush(client)
        total.update(spool.status())
        total['skips'] = dict(spool._db.execute('SELECT cause,count(*) FROM harness_skips GROUP BY cause'))
        total['last_sync'] = int(time.time())
        private_write(folder('data') / (config['source'] + '.status'), total)
        return total


def status(config):
    with open_spool(config) as spool:
        prepare(spool)
        value = spool.status()
        value['skips'] = dict(spool._db.execute('SELECT cause,count(*) FROM harness_skips GROUP BY cause'))
        value['files'] = spool._db.execute('SELECT count(*) FROM harness_files').fetchone()[0]
    try:
        value['last'] = private_read(folder('data') / (config['source'] + '.status'))
    except ClientError:
        value['last'] = None
    value.update(version=VERSION, source=config['source'])
    return value


def wake(source):
    # Native hooks never wait on a socket, a lock or transcript flush. A bounded
    # detached worker reconciles twice; after that the next hook resumes offsets.
    load(source)
    command = ([sys.executable] if getattr(sys, 'frozen', False) else
               [sys.executable, '-m', __name__])
    subprocess.Popen(command + ['sync', '--source', source, '--worker'], stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     # onefile children outlive the parent extraction directory.
                     env={**os.environ, 'PYINSTALLER_RESET_ENVIRONMENT': '1'},
                     start_new_session=True, close_fds=True)


def cause(error):
    return error.code if isinstance(error, ClientError) else type(error).__name__.upper()


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


def main(argv=None):
    parser = argparse.ArgumentParser(prog=PRODUCT)
    parser.add_argument('--version', action='version', version=PRODUCT + ' ' + VERSION)
    sub = parser.add_subparsers(dest='action', required=True)
    for name in ('login', 'sync', 'backfill', 'status', 'diagnose', 'mcp', 'logout', 'parse'):
        command = sub.add_parser(name)
        command.add_argument('--source', choices=SOURCES, required=True)
        if name == 'sync':
            command.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
            command.add_argument('--foreground', action='store_true')
        if name == 'backfill':
            command.add_argument('--steps', type=int, default=0, help='0: run until caught up; Ctrl-C pauses safely')
            command.add_argument('--retry-skips', action='store_true')
        if name == 'parse':
            command.add_argument('path', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == 'parse':
            # Synthetic fixture only, no key or persistent user state needed.
            with tempfile.TemporaryDirectory() as temporary, Spool(
                    Path(temporary)/'queue', source=args.source, host='synthetic', destination=ORIGIN) as spool:
                print(json.dumps(capture(spool, None, paths=[args.path.resolve()], max_lines=2048)))
            return 0
        if args.action == 'login':
            with lease(args.source):
                login(args.source)
            return 0
        if args.action == 'sync' and not (args.worker or args.foreground):
            wake(args.source)
            return 0
        config = load(args.source)
        if args.action == 'mcp':
            remote_mcp(config)
            return 0
        with lease(args.source):
            if args.action == 'logout':
                config_path(args.source).unlink()
                print('Local keys removed; queued records and remote archive retained. Ask operator to revoke keys.')
            elif args.action == 'status':
                print(json.dumps(status(config), sort_keys=True))
            elif args.action in ('sync', 'diagnose'):
                start = time.monotonic()
                result = step(config)
                if args.action == 'sync' and args.worker and time.monotonic()-start < 7:
                    time.sleep(.75)
                    result = step(config)
                if args.action == 'diagnose' or args.foreground:
                    print(json.dumps(result, sort_keys=True))
            elif args.action == 'backfill':
                if args.retry_skips:
                    with open_spool(config) as spool:
                        retry_skipped(spool)
                count = 0
                while True:
                    value = step(config, history=True)
                    print(json.dumps(value, sort_keys=True), flush=True)
                    count += 1
                    if (args.steps and count >= args.steps) or (not value['lines'] and not value['pending']):
                        break
                    time.sleep(.2)
        return 0
    except KeyboardInterrupt:
        print('{"cause":"PAUSED_SAFE_TO_RESUME"}', file=sys.stderr)
        return 130
    except Exception as error:  # noqa: BLE001 -- never expose private values/paths
        code = cause(error)
        if code == 'SYNC_BUSY' and args.action == 'sync':
            return 0
        if args.action != 'parse':
            private_write(folder('data') / (args.source + '.status'), {'cause': code})
        print(json.dumps({'cause': code}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
