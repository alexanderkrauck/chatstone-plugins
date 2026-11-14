# chatstone for Claude Code and Codex

Private conversation capture plus eight read-only archive/search tools. Native
hooks wake a resumable background importer; no OS daemon, Python, Node or GitHub account is
needed. Requires a supported native harness, POSIX sh, curl and stock OS utilities
(including SHA-256). Linux and macOS only; Windows is not supported. The release
workflow targets Ubuntu 24.04 for Linux; older distributions are unqualified.

**Build candidate:** this repository becomes installable only after all four
native jobs pass and an operator publishes the stamped marketplace and release.
Do not install an unstamped candidate (its empty hashes intentionally refuse downloads).

## Install

Claude Code (native CLI, plugin management validated on 2.1.323; earlier versions unqualified):

```text
/plugin marketplace add https://github.com/alexanderkrauck/chatstone-plugins
/plugin install chatstone@chatstone
```

The equivalent shell commands are `claude plugin marketplace add
https://github.com/alexanderkrauck/chatstone-plugins` and `claude plugin install chatstone@chatstone`.
Start a Claude session once to acquire the runner, then in a **separate terminal**:

```sh
"${XDG_DATA_HOME:-$HOME/.local/share}/chatstone/bin/chatstone" login --source claude_code
```

Codex CLI (released 0.169.0 supports this plugin layout):

```sh
codex plugin marketplace add https://github.com/alexanderkrauck/chatstone-plugins
codex plugin add chatstone@chatstone
codex
```

Review and trust the plugin hooks in `/hooks` (updates require review again).
The first trusted wake acquires the runner. In a separate terminal:

```sh
"${XDG_DATA_HOME:-$HOME/.local/share}/chatstone/bin/chatstone" login --source codex
```

Enter an invitation-only enrollment code at the **hidden prompt**, never in chat
or arguments. The operator binds it to your tenant, device name and chosen source.
Keep the same device name for Hermes/Claude/Codex, with separate sources. Restart
the harness after login so its MCP process reconnects. Login starts existing-history import automatically; closing the terminal is safe. No key is stored in harness
settings; both plugins start the local `chatstone mcp --source ...` proxy.

## Capture, status and privacy

Replace `codex` below with `claude_code` for Claude:

```sh
"${XDG_DATA_HOME:-$HOME/.local/share}/chatstone/bin/chatstone" backfill --source codex
"${XDG_DATA_HOME:-$HOME/.local/share}/chatstone/bin/chatstone" status --source codex
"${XDG_DATA_HOME:-$HOME/.local/share}/chatstone/bin/chatstone" diagnose --source codex
```

Live session tails overtake historical queues, including partially read files.
Hooks also fire on user-prompt submission and tool completion; workers keep
checking for delayed transcript writes for 30 seconds after the latest hook.
Imports retry timeouts, disconnects and server restarts automatically with
backoff. A failed original stays with its whole message and batch ID, never
uploads as a silently missing attachment, and does not block unrelated messages.
Retries wait 30/60 seconds; after failure 3 the item is shown as set aside and
waits 5 minutes, then 10/20/40/60 minutes (one-hour cap). The background importer
retries on its own; no new login or command. Later revisions of that same native
message wait behind it; other messages retain live/history priority.
Upload time scales with body size: 1 Mbit/s plus 50% margin and 15 seconds setup,
capped at the server's 120-second body limit (8 MB gets 111 seconds). A body that
cannot finish is set aside immediately as `UPLOAD_BODY_TIMEOUT` (too large for
this connection), with its size, then retried after 5/10/20/40/60 minutes.
Read-tool timeouts are unchanged. Accepted parts are not re-sent for message
receipt polling or restart; a lost positive blob ACK or crash before its local
receipt commits can require one repeat per ambiguous event.
Invalid/revoked keys, disabled ingestion and exhausted capacity stop
with an explanation and a next step. Queued records remain safe.

Default output is plain progress and a final summary; `--json` preserves the
machine-readable form. `status` without `--source` shows both sources, last
hook, last successful/failed upload and reason, plus set-aside count, reasons,
largest bytes and attempts. Skipped record **type names** have counts. New
parsers automatically re-read old skips and enrich session metadata without
resending unchanged messages. `diagnose` runs one bounded real probe.

A short `chatstone` link is created only in an existing, safe user directory
already on PATH. No shell profile is edited; otherwise printed hints contain
the full executable path. Ctrl-C pauses foreground import safely; resume with
the full path above followed by `resume`.

The reader opens only Claude's `projects/` or Codex's `sessions/` and
`archived_sessions/` (honoring `CLAUDE_CONFIG_DIR` and `CODEX_HOME`). Messages,
tool calls/results, session/project provenance, raw records and original inline
attachments go to `https://api.chatstone.goedly.com` over verified HTTPS. Local
file attachment reads are disabled by default; no arbitrary tool paths are read.
Large inline data travels as binary attachments; large native JSON originals are
also retained as attachments, with searchable message text left in place.
The 2 MiB metadata/text envelope still applies; exceptional oversize rows are
counted by reason. **25 MB message support is not claimed.** Archived instructions
are untrusted data. Remote search is the existing eight-tool read-only surface.

Keys live in `${XDG_CONFIG_HOME:-$HOME/.config}/chatstone/native/<source>.json`
(0600, private directory); queue/status in the matching XDG data directory.
Never edit harness headers to paste a key. These two harnesses support stdio;
for remote-only clients, use a trusted credential-provider/environment bearer
header, not a literal key in project configuration. No remote-only flow is
included or qualified here.

## Update and remove

Close both harnesses before updating the shared runner (an older launcher
would otherwise reinstall its old pin). In a terminal:

```sh
claude plugin marketplace update chatstone
claude plugin update chatstone@chatstone --scope user
sh "${CLAUDE_CONFIG_DIR:-$HOME/.claude}/plugins/cache/chatstone/chatstone/0.2.2/launcher.sh" --version
codex plugin marketplace upgrade chatstone
codex plugin remove chatstone@chatstone
codex plugin add chatstone@chatstone
sh "${CODEX_HOME:-$HOME/.codex}/plugins/cache/chatstone/chatstone/0.2.2/launcher.sh" --version
```

Each launcher verifies its exact pin before atomic replacement and resumes
existing imports automatically. A verified obsolete detached worker is stopped automatically; current workers and unrelated/recycled PIDs are left alone. Credentials and queues survive; do **not**
log in again. Restart both harnesses; review and trust changed Codex hooks in
`/hooks` again. Inspect progress with the full runner path followed by `status`.

Uninstall via `/plugin uninstall chatstone@chatstone` (Claude) or
`codex plugin remove chatstone@chatstone` (Codex). Run
`chatstone logout --source codex` (or `claude_code`) using the full binary path
above to remove that source's local keys; ask the operator to revoke them.
Queue/history are retained for recovery. Uninstalling does **not** delete the
hosted archive. Do not remove a shared Hermes directory.

Release assets: `https://github.com/alexanderkrauck/chatstone-plugins/releases`.
The public workflow builds native Linux x86_64/ARM64 and macOS Intel/ARM64 runners,
executes version/fixture/TLS acquisition/hash-refusal smokes on each, and creates
a **draft** release only if all pass. An operator must publish the stamped
marketplace and draft afterwards. No macOS trust claim: signing/notarization and
an actual interactive Mac harness session still need qualification.

MIT for this payload only. Copyright (c) 2026 Alexander Krauck.
