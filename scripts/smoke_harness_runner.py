#!/usr/bin/env python3
"""Public synthetic native smoke: TLS download, exact pin, atomic refusal."""
import argparse
import ctypes
import ctypes.util
import functools
import hashlib
import http.server
import json
import os
import runpy
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('.'))
    args = parser.parse_args()
    root, binary = args.root.resolve(), args.binary.resolve()
    subprocess.run([str(binary), '--version'], check=True)
    fixture = root/'smoke/SYNTHETIC_claude.jsonl'
    if not fixture.exists():
        fixture = root/'harness-integrations/prototype/SYNTHETIC_claude.jsonl'
    parsed = subprocess.run([str(binary), 'parse', '--source', 'claude_code', str(fixture)],
                            capture_output=True, text=True, check=True)
    assert json.loads(parsed.stdout)['admitted'] == 3
    with tempfile.TemporaryDirectory() as temporary:
        # Darwin's stock /var temporary ancestor is a symlink. Resolve only
        # this newly created synthetic root, never relax the real spool guard.
        temp = Path(temporary).resolve()
        # Exercise the bundled native decoder, not just an uncompressed parser.
        rows = [{'type': 'session_meta', 'payload': {'id': 'synthetic-zstd'}}] + [
            {'type': 'response_item', 'payload': {'id': str(i), 'type': 'message', 'role': 'user',
             'content': [{'type': 'input_text', 'text': 'synthetic compressed message'}]}} for i in range(3)]
        raw = ''.join(json.dumps(row)+'\n' for row in rows).encode()
        library = ctypes.util.find_library('zstd')
        if not library:
            prefix = subprocess.check_output(['brew', '--prefix', 'zstd'], text=True).strip()
            library = str(Path(prefix)/'lib/libzstd.1.dylib')
        lib = ctypes.CDLL(library)
        lib.ZSTD_compressBound.argtypes = [ctypes.c_size_t]
        lib.ZSTD_compressBound.restype = ctypes.c_size_t
        lib.ZSTD_compress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        lib.ZSTD_compress.restype = ctypes.c_size_t
        lib.ZSTD_isError.argtypes = [ctypes.c_size_t]
        lib.ZSTD_isError.restype = ctypes.c_uint
        compressed = ctypes.create_string_buffer(lib.ZSTD_compressBound(len(raw)))
        size = lib.ZSTD_compress(compressed, len(compressed), raw, len(raw), 3)
        assert not lib.ZSTD_isError(size)
        archived = temp/'rollout-SYNTHETIC.jsonl.zst'
        archived.write_bytes(compressed.raw[:size])
        result = subprocess.run([str(binary), 'parse', '--source', 'codex', str(archived)],
                                check=True, capture_output=True, text=True)
        assert json.loads(result.stdout)['admitted'] == 3
        cert = temp/'cert.pem'
        key = temp/'key.pem'
        config = temp/'cert.cnf'
        config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=127.0.0.1\n[ext]\nsubjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:TRUE\n')
        subprocess.run(['openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '1',
                        '-config', str(config), '-out', str(cert), '-keyout', str(key)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        assets = temp/'assets'
        assets.mkdir()
        staged = assets/binary.name
        shutil.copyfile(binary, staged)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0),
            functools.partial(Quiet, directory=str(assets)))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            template = root/'plugins/claude-code/launcher.sh'
            if not template.exists():
                template = root/'harness-integrations/launcher.sh'
            launcher = temp/'launcher.sh'
            shutil.copyfile(template, launcher)
            settings = root/'runner/src/chatstone/client/native_product.py'
            if not settings.exists():
                settings = root/'src/chatstone/client/native_product.py'
            product = runpy.run_path(str(settings))['PRODUCT']
            target = binary.name.removeprefix(product+'-')
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            release = temp/'release.conf'
            release.write_text(f"product='{product}'\nrelease_base='https://127.0.0.1:{server.server_port}'\n" +
                ''.join(f"{t.replace('-', '_')}='{digest if t == target else ''}'\n" for t in
                        ('linux-arm64', 'linux-amd64', 'darwin-arm64', 'darwin-amd64')))
            env = {**os.environ, 'XDG_DATA_HOME': str(temp/'user data'), 'CURL_CA_BUNDLE': str(cert)}
            command = ['sh', str(launcher), '--version']
            result = subprocess.run(command, check=False, env=env, capture_output=True, text=True)
            assert result.returncode == 0, 'LAUNCHER_DOWNLOAD_SMOKE_FAILED'
            installed = temp/'user data'/product/'bin'/product
            assert hashlib.sha256(installed.read_bytes()).hexdigest() == digest
            if os.uname().sysname == 'Darwin':
                # Assess the actual curl-acquired bytes, without removing any
                # attributes or applying a developer signature/trust bypass.
                for diagnostic in (['xattr', '-l', str(installed)],
                                   ['codesign', '-dv', '--verbose=2', str(installed)]):
                    subprocess.run(diagnostic, check=False)
                subprocess.run(['xattr', '-w', 'com.apple.quarantine',
                                '0081;00000000;NativePluginSmoke;', str(installed)], check=True)
                subprocess.run([str(installed), '--version'], env=env, check=True)
                assessed = subprocess.run(['spctl', '--assess', '--type', 'execute', str(installed)], check=False)
                print(json.dumps({'mac_curl_quarantine_start': True,
                                  'gatekeeper_assessment_exit': assessed.returncode}), flush=True)
            # A damaged cache forces acquisition; a bad server object must not
            # become executable or replace the installed bytes.
            installed.write_bytes(b'old nonexecutable data')
            staged.write_bytes(b'corrupted release')
            refusal = subprocess.run(command, check=False, env=env, capture_output=True, text=True)
            assert refusal.returncode != 0 and 'SHA256_MISMATCH' in refusal.stderr
            assert installed.read_bytes() == b'old nonexecutable data'
            # A detached onefile child must still reach Python after its parent
            # has exited and removed its extraction directory. Use a synthetic
            # key and a reserved, non-listening loopback port; no service is mocked.
            config_root = temp/'config'/product/'native'
            config_root.mkdir(parents=True, mode=0o700)
            token = '00000000-0000-0000-0000-000000000000.'+'synthetic_'+'x'*32
            with socket.socket() as unavailable:
                unavailable.bind(('127.0.0.1', 0))
                private = config_root/'codex.json'
                private.write_text(json.dumps({'source': 'codex', 'device': 'synthetic', 'roots': [],
                    'origin': 'http://127.0.0.1:'+str(unavailable.getsockname()[1]),
                    'read_key': token, 'ingest_key': token}))
                private.chmod(0o600)
                worker_env = {**env, 'XDG_CONFIG_HOME': str(temp/'config'), 'CHATSTONE_TEST_LOOPBACK': '1',
                              'TMPDIR': str(temp)}
                subprocess.run([str(binary), 'sync', '--source', 'codex'], env=worker_env, check=True)
                status_file = temp/'user data'/product/'native/codex.status'
                deadline = time.monotonic()+10
                while not status_file.exists() and time.monotonic() < deadline:
                    time.sleep(.1)
                assert status_file.exists(), 'DETACHED_FROZEN_WORKER_DID_NOT_START'
                actual_status = json.loads(status_file.read_text())
                assert actual_status == {'cause': 'TRANSPORT_ERROR'}, actual_status
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)
    print(json.dumps({'smoke': 'version_parse_zstd_tls_acquire_hash_refusal', 'passed': True}))


if __name__ == '__main__':
    main()
