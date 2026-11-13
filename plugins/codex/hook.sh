#!/bin/sh
# Never block a turn; hook input is private and intentionally unused.
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
(sh "$here/launcher.sh" sync "$@" </dev/null >/dev/null 2>&1 & )
printf '{}\n'
