#!/bin/sh
# Never block a turn; pass private input only to the detached local wake.
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec 3<&0
(sh "$here/launcher.sh" sync --hook "$@" <&3 >/dev/null 2>&1 & )
exec 3<&-
printf '{}\n'
