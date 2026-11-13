---
name: backfill
description: Backfill the private conversation archive.
---

Run in the user's terminal; report only safe counts and cause codes. Do not read credentials or conversation files.

```sh
"${XDG_DATA_HOME:-$HOME/.local/share}/chatstone/bin/chatstone" backfill --source claude_code
```

Newest sessions first; records inside each session stay in native order. Ctrl-C pauses safely. Live appends to completed sessions overtake queued history. Use --retry-skips after upgrading to retry bad rows.
