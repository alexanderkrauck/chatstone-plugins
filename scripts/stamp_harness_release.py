#!/usr/bin/env python3
"""Pin exact native release artifacts into both plugin launchers."""
import argparse
import ast
import hashlib
import json
from pathlib import Path

TARGETS = ('linux-arm64', 'linux-amd64', 'darwin-arm64', 'darwin-amd64')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path('.'))
    parser.add_argument('--assets', type=Path)
    parser.add_argument('--require-all', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve()
    config = {node.targets[0].id: ast.literal_eval(node.value)
        for node in ast.parse((root/'runner/src/chatstone/client/native_product.py').read_bytes()).body
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in ('PRODUCT', 'VERSION', 'REPOSITORY')}
    PRODUCT, REPOSITORY = config['PRODUCT'], config['REPOSITORY']
    RELEASE = 'v'+config['VERSION']
    pins = {}
    for target in TARGETS:
        candidate = args.assets/(PRODUCT+'-'+target) if args.assets else None
        pins[target] = hashlib.sha256(candidate.read_bytes()).hexdigest() if candidate and candidate.is_file() else ''
    if args.require_all and not all(pins.values()):
        raise SystemExit('FOUR_NATIVE_ARTIFACTS_REQUIRED')
    text = f"product='{PRODUCT}'\nversion='{RELEASE}'\nrelease_base='https://github.com/{REPOSITORY}/releases/download/{RELEASE}'\n"
    text += ''.join(f"{target.replace('-', '_')}='{digest}'\n" for target, digest in pins.items())
    for harness in ('claude-code', 'codex'):
        (root/'plugins'/harness/'release.conf').write_text(text)
    path = root/'build.json'
    value = json.loads(path.read_text())
    value['release_sha256'] = pins
    # Retain the provenance identity; cover only payload paths, never .git.
    names = set(value['sha256']) | {'plugins/'+h+'/release.conf' for h in ('claude-code', 'codex')}
    value['sha256'] = {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in sorted(names)}
    path.write_text(json.dumps(value, sort_keys=True)+'\n')
    print(json.dumps({'pinned': sum(bool(v) for v in pins.values()), 'required': 4}))


if __name__ == '__main__':
    main()
