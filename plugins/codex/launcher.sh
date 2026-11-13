#!/bin/sh
# Pinned acquisition; POSIX sh + curl and stock macOS/Linux utilities only.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$here/release.conf"
fail() { printf '%s\n' "$1" >&2; exit 1; }
case $(uname -s) in Linux) os=linux ;; Darwin) os=darwin ;; *) fail PLATFORM_UNSUPPORTED ;; esac
case $(uname -m) in aarch64|arm64) arch=arm64 ;; x86_64|amd64) arch=amd64 ;; *) fail PLATFORM_UNSUPPORTED ;; esac
case "$os-$arch" in
 linux-arm64) expected=$linux_arm64 ;; linux-amd64) expected=$linux_amd64 ;;
 darwin-arm64) expected=$darwin_arm64 ;; darwin-amd64) expected=$darwin_amd64 ;;
esac
[ ${#expected} -eq 64 ] || fail RELEASE_NOT_QUALIFIED
case "$expected" in *[!0-9a-f]*) fail RELEASE_NOT_QUALIFIED ;; esac
hash() {
 if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d ' ' -f 1
 elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d ' ' -f 1
 else fail SHA256_TOOL_UNAVAILABLE; fi
}
base=${XDG_DATA_HOME:-"$HOME/.local/share"}/$product
bin=$base/bin
umask 077
mkdir -p "$bin"
[ ! -L "$bin" ] || fail INSTALL_DIRECTORY_UNSAFE
runner=$bin/$product
if [ ! -f "$runner" ] || [ -L "$runner" ] || [ "$(hash "$runner")" != "$expected" ]; then
 stage=$(mktemp -d "$bin/.acquire.XXXXXXXX")
 trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
 asset=$product-$os-$arch
 curl --proto '=https' --tlsv1.2 -fLsS --connect-timeout 10 --max-time 90 \
  "$release_base/$asset" -o "$stage/$product" || fail DOWNLOAD_FAILED
 [ "$(hash "$stage/$product")" = "$expected" ] || fail SHA256_MISMATCH
 chmod 700 "$stage/$product"
 mv -f -- "$stage/$product" "$runner"
 rm -rf -- "$stage"
 trap - EXIT HUP INT TERM
fi
# A private executable scratch directory avoids a noexec system temp on Linux.
mkdir -p "$base/native/tmp"
chmod 700 "$base/native/tmp"
TMPDIR=$base/native/tmp "$runner" "$@"
