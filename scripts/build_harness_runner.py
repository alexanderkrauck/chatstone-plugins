#!/usr/bin/env python3
"""Freeze the shared Python client as one native executable; build host only."""
import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = root/'src'
    if not source.is_dir():
        source = root/'runner/src'
    sys.path.insert(0, str(source))
    from chatstone.client.native_product import PRODUCT
    system = 'darwin' if sys.platform == 'darwin' else 'linux'
    arch = 'arm64' if platform.machine() in ('aarch64', 'arm64') else 'amd64'
    name = f'{PRODUCT}-{system}-{arch}'
    args.out.mkdir(parents=True, exist_ok=True)
    entry = args.out/'entry.py'
    entry.write_text('from chatstone.client.native_runner import main\nraise SystemExit(main())\n')
    library = os.environ.get('CHATSTONE_ZSTD_LIBRARY')
    if not library:
        candidates = list(Path('/usr/lib').glob('*/libzstd.so.1'))
        if sys.platform == 'darwin':
            prefix = subprocess.check_output(['brew', '--prefix', 'zstd'], text=True).strip()
            candidates = [Path(prefix)/'lib/libzstd.1.dylib']
        library = str(next((p for p in candidates if p.is_file()), ''))
    if not library or not Path(library).is_file():
        raise SystemExit('BUILD_ZSTD_LIBRARY_REQUIRED')
    command = [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile',
        '--name', name, '--paths', str(source), '--add-binary', library + ':.',
        '--distpath', str(args.out), '--workpath', str(args.out/'work'),
        '--specpath', str(args.out), str(entry)]
    with (args.out/'build.log').open('wb') as log:
        subprocess.run(command, stdout=log, stderr=log, check=True)
    binary = args.out/name
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    (args.out/(name+'.sha256')).write_text(digest+'  '+name+'\n')
    print(json.dumps({'artifact': name, 'bytes': binary.stat().st_size, 'sha256': digest}))


if __name__ == '__main__':
    main()
