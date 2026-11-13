---
name: login
description: Login the private conversation archive.
---

Never ask for or accept a code in chat. Tell the user to run this in a separate interactive terminal after the first plugin wake:

```sh
"${XDG_DATA_HOME:-$HOME/.local/share}/chatstone/bin/chatstone" login --source codex
```

The hidden prompt accepts an invitation code bound to this device and source. Restart the harness after login so MCP reconnects. Never place keys in harness settings.
