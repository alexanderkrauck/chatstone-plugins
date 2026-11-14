"""Native JSONL projection for live Claude Code and Codex capture.

Metadata/duplicate event mirrors are not messages. Reasoning is retained as a
part, never promoted to ordinary text. No network or arbitrary path fetching.
The legacy explicit-import parsers remain unchanged.
"""
from __future__ import annotations

import hashlib
import mimetypes
import re
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .contracts import Attachment, ParseLimits, Part
from .harnesses import _Content
from .normalization import canonical
from .policy import SourceDenied, checked_path, open_explicit


class SkipRecord(ValueError):
    """Content-free skip-ledger cause."""


def _native(value):
    if not isinstance(value, str) or not value or '\x00' in value or len(value.encode()) > 4096:
        raise SkipRecord('IDENTITY_INVALID')
    return value


def _parent(source):
    if not isinstance(source, dict):
        return None
    subagent = source.get('subagent', {})
    if isinstance(subagent, dict):
        spawn = subagent.get('thread_spawn', {})
        if isinstance(spawn, dict):
            return spawn.get('parent_thread_id')
    return None


class Content(_Content):
    def __init__(self, limits, roots):
        super().__init__(limits)
        self.roots = tuple(checked_path(Path(r)) for r in roots)

    def local(self, value):
        """Only explicit attachment blocks within user-approved roots; never tool arguments."""
        if not isinstance(value, str):
            self.warnings.append('ATTACHMENT_REFERENCE_UNREAD')
            return
        url = urlsplit(value)
        if url.scheme not in ('', 'file') or url.netloc:
            self.warnings.append('ATTACHMENT_REFERENCE_UNREAD')
            return
        path = Path(unquote(url.path))
        try:
            path = checked_path(path)
            if not any(path.is_relative_to(root) for root in self.roots):
                raise SourceDenied('ATTACHMENT_DENIED')
            with open_explicit(path) as handle:
                data = handle.read(self.limits.max_attachment_bytes + 1)
            if len(data) > self.limits.max_attachment_bytes:
                self.parts.append(Part(kind='oversize', size=len(data)))
                self.warnings.append('ATTACHMENT_OVERSIZE')
                return
            # extract_content sniffs the original bytes and makes hash-addressed parts.
            from .binary import extract_binary
            extracted = extract_binary(data, limits=self.limits)
            mime = mimetypes.guess_type(path.name)[0] or 'application/octet-stream'
            self.parts.extend(replace(p, content_type=mime) for p in extracted.parts)
            self.attachments.extend(replace(a, content_type=mime) for a in extracted.attachments)
        except (SourceDenied, OSError):
            self.warnings.append('ATTACHMENT_UNAVAILABLE')

    def read(self, value):
        if not isinstance(value, list):
            return super().read(value)
        for block in value:
            if not isinstance(block, dict):
                super().read([block])
                continue
            kind = block.get('type')
            source = block.get('source')
            if kind in ('document', 'file') and isinstance(source, dict):
                if source.get('type') == 'base64':
                    self.inline(source.get('media_type'), source.get('data'))
                elif source.get('type') == 'file':
                    self.local(source.get('path'))
                else:
                    self.warnings.append('ATTACHMENT_REFERENCE_UNREAD')
            elif kind == 'input_file':
                data = block.get('file_data')
                if isinstance(data, str) and data.startswith('data:'):
                    extracted = self.__class__(self.limits, self.roots)
                    extracted.read([{'type': 'input_image', 'image_url': data}])
                    self.parts.extend(extracted.parts)
                    self.attachments.extend(extracted.attachments)
                    self.warnings.extend(extracted.warnings)
                else:
                    self.local(block.get('file_path'))
            elif kind in ('input_image', 'image') and isinstance(block.get('image_url'), str) and not block['image_url'].startswith('data:'):
                self.local(block['image_url'])
            elif kind == 'image' and isinstance(block.get('data'), str):
                self.inline(block.get('mimeType', 'image/png'), block['data'])
            else:
                super().read([block])


def session_context(raw, ctx, source):
    """Native metadata is separate from message fingerprints and revisions."""
    payload = raw.get('payload') if source == 'codex' else raw
    payload = payload if isinstance(payload, dict) else {}
    message = raw.get('message') if isinstance(raw.get('message'), dict) else payload
    session = raw.get('sessionId') if source == 'claude_code' else payload.get('id') if raw.get('type') == 'session_meta' else None
    if isinstance(session, str):
        ctx['session'] = session
    for key in ('cwd', 'model'):
        value = payload.get(key) or message.get(key)
        if isinstance(value, str) and len(value.encode()) <= 4096 and '\x00' not in value:
            ctx[key] = value
    stamp = raw.get('timestamp') or (payload.get('timestamp') if raw.get('type') == 'session_meta' else None)
    try:
        parsed = datetime.fromisoformat(stamp)
        if parsed.utcoffset() is None:
            raise ValueError
        if not ctx.get('started_at') or parsed < datetime.fromisoformat(ctx['started_at']):
            ctx['started_at'] = stamp
        if not ctx.get('ended_at') or parsed > datetime.fromisoformat(ctx['ended_at']):
            ctx['ended_at'] = stamp
    except (TypeError, ValueError):
        pass
    category = raw.get('type')
    title, origin = None, None
    if category in ('custom-title', 'ai-title', 'summary'):
        title = raw.get('customTitle') or raw.get('aiTitle') or raw.get('summary')
        origin = 'custom' if category == 'custom-title' else 'summary'
    elif source == 'codex' and category == 'session_meta':
        title = payload.get('thread_name') or payload.get('title')
        origin = 'custom'
    if not ctx.get('title') and message.get('role') == 'user':
        content = message.get('content')
        title = content if isinstance(content, str) else ' '.join(
            b.get('text', '') for b in content or [] if isinstance(b, dict) and b.get('type') in ('text', 'input_text'))
        origin = 'first_prompt'
    ranks = {'first_prompt': 1, 'summary': 2, 'custom': 3}
    if isinstance(title, str) and title.strip() and ranks.get(origin, 0) >= ranks.get(ctx.get('title_source'), 0):
        # The harness lists a short first-prompt preview, not an entire prompt.
        ctx['title'] = ' '.join(title.split())[:200] if origin == 'first_prompt' else title[:1000]
        ctx['title_source'] = origin
    return ctx


def session_payload(ctx, source, path, *, session=None, kind=None, parent=None):
    native = session or ctx.get('session')
    if not isinstance(native, str) or not native:
        return None
    if session is None and source == 'claude_code' and path.stem.startswith('agent-'):
        parent = path.parent.parent.name if path.parent.name == 'subagents' else native
        native, kind = parent+':agent:'+path.stem[6:], 'subagent'
    return {'native_session_id': native, 'kind': kind or ('subagent' if ctx.get('subagent') else 'interactive'),
            'title': ctx.get('title'), 'model': ctx.get('model'), 'cwd': ctx.get('cwd'),
            'project': ctx.get('project') or ctx.get('cwd'), 'started_at': ctx.get('started_at'),
            'ended_at': ctx.get('ended_at'), 'parent_native_id': parent or ctx.get('parent'),
            'meta': {'source': source, 'title_source': ctx.get('title_source'), 'end_reason': 'last_record'}}


def opaque_content(value):
    """Unknown native shapes with data are retained/searchable, never silently lost."""
    if not isinstance(value, dict):
        return None
    data = {k: v for k, v in value.items() if k not in ('type', 'timestamp', 'sessionId', 'uuid', 'parentUuid', 'cwd', 'version')}
    return canonical(data).decode() if data else None


def project(raw, *, source, path, context, limits=None, attachment_roots=()):
    """Return projected records and context; caller assigns durable IDs/order.

    Codex event_msg is a mirror of response_item, not a second user/assistant
    copy. Compaction is a system record, not replay of replacement_history.
    """
    limits = limits or ParseLimits()
    if not isinstance(raw, dict):
        raise SkipRecord('JSON_OBJECT_REQUIRED')
    ctx = session_context(raw, dict(context), source.source)
    fallback = False
    category = raw.get('type')
    if source.source == 'claude_code':
        message = raw.get('message')
        if category not in ('user', 'assistant') or not isinstance(message, dict):
            journal = isinstance(raw.get('key'), str) and re.fullmatch(r'v[0-9]+:[0-9a-f]{64}', raw['key']) and isinstance(raw.get('agentId'), str)
            if (category in ('started', 'failed') and journal and
                    set(raw) <= {'type', 'key', 'agentId', 'remoteSessionId', 'label', 'phaseTitle', 'phaseIndex'} or
                    category in ('launched', 'restoring', 'restored', 'resumed') and
                    set(raw) <= {'type', 'hiddenScriptSha256'}):
                return [], ctx, 'LIFECYCLE_RECORD'
            if category == 'result' and (journal or isinstance(raw.get('session_id'), str)):
                # Workflow return values can be transformed/arbitrary data, not
                # necessarily a duplicate of an assistant transcript message.
                result = raw.get('result', raw.get('errors', ''))
                message = {'role': 'system', 'content': result if isinstance(result, str) else canonical(result).decode()}
                if journal:
                    ctx['session'] = 'workflow:' + hashlib.sha256(str(path.parent).encode()).hexdigest()
                else:
                    ctx['session'] = raw['session_id']
            elif category == 'system' and raw.get('subtype') == 'compact_boundary':
                message = {'role': 'system', 'content': raw.get('content', '')}
            elif category == 'attachment' and raw.get('rendered'):
                # Current Claude persists model-visible system/user context in
                # rendered blocks, not in a user/assistant message envelope.
                message = {'role': raw.get('renderedRole') if raw.get('renderedRole') in ('user', 'assistant') else 'system',
                           'content': raw['rendered']}
            elif category == 'summary' and isinstance(raw.get('summary'), str):
                message = {'role': 'system', 'content': raw['summary']}
            elif category in ('custom-title', 'ai-title', 'last-prompt', 'file-history-snapshot', 'tag', 'agent-name', 'agent-color', 'pr-link'):
                return [], ctx, 'METADATA_RECORD'
            elif opaque_content(raw):
                message = {'role': 'system', 'content': opaque_content(raw)}
                fallback = True
            else:
                return [], ctx, 'UNKNOWN_RECORD'
        session = raw.get('sessionId') or ctx.get('session')
        if not session and category == 'summary':
            # Summary-only files cannot safely invent a session from a filename.
            return [], ctx, 'SUMMARY_WITHOUT_SESSION'
        session = _native(session)
        ctx.update(session=session, cwd=raw.get('cwd', ctx.get('cwd')))
        parent, kind = None, 'interactive'
        if path.stem.startswith('agent-'):
            parent = path.parent.parent.name if path.parent.name == 'subagents' else session
            session = parent + ':agent:' + path.stem[6:]
            kind = 'subagent'
        elif raw.get('isSidechain'):
            branches = dict(ctx.get('branches', {}))
            parent = session
            ancestor = branches.get(raw.get('parentUuid'), raw.get('parentUuid') or raw.get('uuid'))
            branches[raw.get('uuid')] = ancestor
            ctx['branches'] = branches
            session += ':sidechain:' + _native(ancestor)
            kind = 'subagent'
        native = raw.get('uuid')
        derived = native is None
        if derived:
            native = 'record-sha256:' + hashlib.sha256(canonical(raw)).hexdigest()
        native = _native(native)
        content = message.get('content', '')
        role = message.get('role')
        if role not in ('user', 'assistant', 'system'):
            raise SkipRecord('ROLE_INVALID')
        # Native blocks can split a user envelope into text and tool-result rows.
        blocks = content if isinstance(content, list) else None
        results = [(i, b) for i, b in enumerate(blocks or []) if isinstance(b, dict) and b.get('type') == 'tool_result']
        ordinary = [b for b in blocks if not isinstance(b, dict) or b.get('type') != 'tool_result'] if results else content
        fragments = [(native, role, ordinary, None)] if ordinary or not results else []
        fragments += [(native + ':tool_result:' + str(i), 'tool', b.get('content', ''), b.get('tool_use_id')) for i, b in results]
    elif source.source == 'codex':
        payload = raw.get('payload')
        if not isinstance(payload, dict):
            raise SkipRecord('PAYLOAD_INVALID')
        if category == 'session_meta':
            ctx.update(session=_native(payload.get('id')), cwd=payload.get('cwd'),
                       parent=payload.get('parent_thread_id') or _parent(payload.get('source')) or payload.get('forked_from_id'),
                       subagent=bool(payload.get('parent_thread_id') or _parent(payload.get('source'))))
            return [], ctx, None
        if category == 'turn_context':
            ctx['cwd'] = payload.get('cwd', ctx.get('cwd'))
            return [], ctx, None
        if category == 'event_msg' and payload.get('type') in ('user_message', 'agent_message', 'agent_reasoning', 'agent_reasoning_raw_content', 'agent_reasoning_section_break', 'task_complete'):
            return [], ctx, 'MIRROR_EVENT'
        if category in ('dynamic_tools_updated', 'inter_agent_communication_metadata', 'token_usage_record', 'security_risk_score') or category == 'event_msg' and payload.get('type') in ('token_count', 'task_started', 'turn_started', 'turn_complete'):
            return [], ctx, 'METADATA_RECORD'
        session = _native(ctx.get('session'))
        parent, kind = ctx.get('parent'), 'subagent' if ctx.get('subagent') else 'interactive'
        item = payload.get('type')
        native = payload.get('id')
        derived = not native
        if derived:
            # Includes timestamp, role and payload; no line-offset IDs that shift on compaction.
            native = 'record-sha256:' + hashlib.sha256(canonical(raw)).hexdigest()
        native = _native(native)
        parsed = Content(limits, attachment_roots)
        call = None
        if category == 'compacted':
            role = 'system'
            parsed.read(payload.get('message', ''))
        elif category != 'response_item':
            if not opaque_content(payload):
                return [], ctx, 'UNKNOWN_RECORD'
            role, fallback = 'system', True
            parsed.read(canonical(payload).decode())
        elif item == 'message':
            role = payload.get('role')
            if role not in ('user', 'assistant', 'system', 'developer'):
                raise SkipRecord('ROLE_INVALID')
            role = 'system' if role == 'developer' else role
            parsed.read(payload.get('content', []))
        elif item in ('function_call', 'custom_tool_call', 'local_shell_call', 'web_search_call', 'tool_search_call'):
            role = 'assistant'
            args = payload.get('arguments', '') if item == 'function_call' else payload.get('input', payload.get('action', payload.get('arguments', '')))
            parsed.part('tool_call', args if isinstance(args, str) else canonical(args).decode(),
                        call_id=payload.get('call_id'), name=payload.get('name') or item)
        elif item in ('function_call_output', 'custom_tool_call_output', 'mcp_tool_call_output'):
            role, call = 'tool', payload.get('call_id')
            output = payload.get('output', '')
            if isinstance(output, dict):
                output = output.get('content', canonical(output).decode())
            parsed.read(output)
        elif item == 'reasoning':
            role = 'assistant'
            for block in (payload.get('summary') or [])+(payload.get('content') or []):
                if isinstance(block, dict):
                    parsed.part('reasoning', block.get('text', ''))
            # Encrypted reasoning stays raw-only; never attempt decrypting it.
        elif item in ('compaction', 'context_compaction'):
            role = 'system'
            parsed.read(payload.get('summary') or payload.get('content') or payload.get('message', ''))
        else:
            if not opaque_content(payload):
                return [], ctx, 'UNKNOWN_RESPONSE_ITEM'
            role, fallback = 'system', True
            parsed.read(canonical(payload).decode())
        fragments = [(native, role, parsed, call)]
    else:
        raise ValueError('SOURCE_UNSUPPORTED')
    for value in (ctx.get('cwd'), parent):
        if value is not None and (not isinstance(value, str) or '\x00' in value or len(value.encode()) > 4096):
            raise SkipRecord('SESSION_METADATA_INVALID')
    metadata = canonical({'schema': 'chatstone.session.v1', 'project': ctx.get('cwd'),
                          'cwd': ctx.get('cwd'), 'parent': parent, 'kind': kind}).decode()
    if len(metadata.encode()) > 4096:
        raise SkipRecord('SESSION_METADATA_OVERSIZE')
    records = []
    # The shared uploader already stages attachment originals as binary blobs.
    # Keep a large native envelope there too rather than duplicating its inline
    # base64 in the 2 MiB JSON request. The small raw sidecar identifies the
    # complete original; no text or unknown native fields are thrown away.
    original = canonical(raw)
    timestamp = raw.get('timestamp')
    detached = None
    if len(original) > 512_000:
        if len(original) > limits.max_attachment_bytes:
            raise SkipRecord('RAW_ORIGINAL_OVERSIZE')
        digest = hashlib.sha256(original).hexdigest()
        detached = Attachment(digest, len(original), 'application/json', original, False)
        raw = {'schema': 'chatstone.native-original.v1', 'sha256': digest,
               'size': len(original), 'content_type': 'application/json'}
    for native, role, content, call in fragments:
        parsed = content if isinstance(content, Content) else Content(limits, attachment_roots)
        if not isinstance(content, Content):
            parsed.read(content)
        if derived:
            parsed.warnings.append('NATIVE_ID_DERIVED')
        if fallback:
            parsed.warnings.append('UNRECOGNIZED_RECORD_CAPTURED')
        if detached is not None:
            parsed.attachments.append(detached)
            parsed.parts.append(Part(kind='attachment', sha256=detached.sha256,
                                     size=detached.size, content_type=detached.content_type))
            parsed.warnings.append('RAW_ORIGINAL_ATTACHMENT')
        records.append(parsed.emit(raw=raw, identity=source, session=session,
            native_id=native, seq=0, ts=timestamp, native_role=role,
            native_source=metadata, tool_result=(call, None) if role == 'tool' else None))
    return records, ctx, None
