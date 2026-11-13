"""Bounded, origin-pinned synchronous REST transport (no automatic retries)."""
import asyncio
import json
import math
import os
import re
from time import monotonic
from urllib.parse import urlsplit

import httpx

TOOL_NAMES = ('list_sources', 'search_messages', 'search_messages_regex', 'get_message',
              'get_session', 'get_attachment', 'list_sessions', 'stats')
SERVER_CODES = frozenset([
    'INVALID_KEY', 'INVALID_HOST', 'INVALID_ORIGIN', 'INVALID_REQUEST', 'REQUEST_TOO_LARGE',
    'UNSUPPORTED_MEDIA_TYPE', 'INVALID_FILTER', 'INVALID_REGEX', 'INVALID_CURSOR', 'CURSOR_STALE',
    'KEY_SCOPE_CHANGED', 'NOT_FOUND', 'METHOD_NOT_ALLOWED', 'UNSUPPORTED_CAPABILITY',
    'RESULT_TOO_LARGE', 'INCOMPLETE_SCOPE', 'REQUEST_TIMEOUT', 'RETRIEVAL_TIMEOUT', 'SEARCH_TIMEOUT',
    'REGEX_TIMEOUT', 'RATE_LIMITED', 'INGEST_DISABLED', 'SERVICE_UNAVAILABLE',
    'INGEST_CAPACITY_EXCEEDED',
])
TOKEN = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
                   r'\.[A-Za-z0-9_-]{32,128}')
MAX_JSON_BYTES = 262144


class ClientError(Exception):
    """Coded errors deliberately contain no server body, URL or credentials."""

    def __init__(self, code, *, status=None):
        super().__init__(code)
        self.code = code
        self.status = status


def encode_json(value, maximum=MAX_JSON_BYTES):
    result = bytearray()
    try:
        encoder = json.JSONEncoder(ensure_ascii=False, allow_nan=False, separators=(',', ':'))
        for chunk in encoder.iterencode(value):
            result.extend(chunk.encode('utf-8'))
            if len(result) > maximum:
                raise ClientError('REQUEST_TOO_LARGE')
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ClientError('INVALID_REQUEST') from None
    return bytes(result)


def decode_json(body):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def finite(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError
        return number

    try:
        value = json.loads(body, object_pairs_hook=unique, parse_constant=finite, parse_float=finite)
        if type(value) is not dict:
            raise ValueError
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise ClientError('INVALID_RESPONSE') from None


class Client:
    """Read client. Call from synchronous code, not inside a running event loop.

    HTTPS certificate/hostname validation is mandatory. The only HTTP escape
    hatch is an explicit numeric loopback test origin. Secret getters must be
    trusted, nonblocking local lookups (e.g. a preloaded OS-keychain value).
    """

    tool_names = TOOL_NAMES
    key_environment = 'CHATSTONE_READ_KEY'

    def __init__(self, base_url, *, secret_getter=None, allow_loopback_http=False, timeout=10):
        try:
            if not isinstance(base_url, str) or any(c.isspace() or ord(c) < 32 for c in base_url):
                raise ValueError
            url = urlsplit(base_url)
            if (not url.hostname or url.username is not None or url.password is not None
                    or url.path not in ('', '/') or url.query or url.fragment
                    or any(c in base_url for c in ('\\', '?', '#', '%'))):
                raise ValueError
            if url.scheme != 'https' and not (
                    allow_loopback_http is True and url.scheme == 'http'
                    and url.hostname in ('127.0.0.1', '::1')):
                raise ValueError
            if url.port is not None and not 1 <= url.port <= 65535:
                raise ValueError
        except (ValueError, TypeError):
            raise ClientError('INVALID_URL') from None
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= 300):
            raise ClientError('INVALID_TIMEOUT')
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self._secret_getter = secret_getter or (lambda: os.environ.get(self.key_environment))
        self._ssl_context = None

    def pages(self, operation, **kwargs):
        """Yield unchanged envelopes; exhaustion proves counts, not a partial success.

        Starts at the first page. One total deadline spans all pages, including
        caller processing time. No silent page limit and no accumulating results.
        """
        arrays = {'search_messages': 'hits', 'search_messages_regex': 'hits',
                  'list_sessions': 'sessions', 'get_session': 'messages'}
        if operation not in arrays or kwargs.get('cursor'):
            raise ClientError('INVALID_OPERATION')
        end = monotonic() + self.timeout
        seen, count, total = set(), 0, None
        while True:
            value = self._request('/api/v1/' + operation, encode_json(kwargs), deadline=end)
            items, current = value.get(arrays[operation]), value.get('total_count')
            returned, more = value.get('returned_count'), value.get('has_more')
            cursor = value.get('next_cursor')
            if (type(items) is not list or type(current) is not int or current < 0
                    or type(returned) is not int or returned != len(items)
                    or type(more) is not bool or (total is not None and total != current)):
                raise ClientError('PAGINATION_INVALID')
            total = current
            count += returned
            if (count > total or (more and (not items or count >= total
                    or not isinstance(cursor, str) or not 0 < len(cursor) <= 8192
                    or cursor in seen)) or (not more and (cursor is not None or count != total))):
                raise ClientError('PAGINATION_INVALID')
            yield value
            if not more:
                return
            seen.add(cursor)
            kwargs = {**kwargs, 'cursor': cursor}

    def query(self, operation, **kwargs):
        if operation not in TOOL_NAMES:
            raise ClientError('INVALID_OPERATION')
        return self._request('/api/v1/' + operation, encode_json(kwargs))

    def _request(self, path, body, *, media='application/json', deadline=None):
        end = min(deadline or float('inf'), monotonic() + self.timeout)
        try:
            token = self._secret_getter()
            if not isinstance(token, str) or not TOKEN.fullmatch(token):
                raise ValueError
        except Exception:  # noqa: BLE001 -- secret providers may raise arbitrary private diagnostics
            raise ClientError('INVALID_KEY') from None
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise ClientError('SYNC_CLIENT_IN_EVENT_LOOP')
        try:
            return asyncio.run(self._send(path, body, media, token, end))
        except (TimeoutError, httpx.TimeoutException):
            raise ClientError('DEADLINE_EXCEEDED') from None
        except httpx.HTTPError:
            raise ClientError('TRANSPORT_ERROR') from None

    async def _send(self, path, body, media, token, end):
        remaining = end - monotonic()
        if remaining <= 0:
            raise ClientError('DEADLINE_EXCEEDED')
        async with asyncio.timeout(remaining):
            if self._ssl_context is None:
                try:
                    # Match httpx's verified default CA bundle, not ambient SSL settings.
                    self._ssl_context = httpx.create_ssl_context(verify=True, trust_env=False)
                except Exception:  # noqa: BLE001 -- CA setup can contain private diagnostics
                    raise ClientError('TRANSPORT_ERROR') from None
            async with httpx.AsyncClient(verify=self._ssl_context, follow_redirects=False, trust_env=False,
                                         timeout=remaining) as http:
                # Synchronous TLS/client setup cannot yield to the timeout callback.
                if monotonic() >= end:
                    raise ClientError('DEADLINE_EXCEEDED')
                headers = {'Authorization': 'Bearer ' + token, 'Content-Type': media,
                           'Accept-Encoding': 'identity'}
                async with http.stream('POST', self.base_url + path, content=body,
                                       headers=headers) as response:
                    if 300 <= response.status_code < 400:
                        raise ClientError('REDIRECT_REFUSED', status=response.status_code)
                    if response.headers.get('content-encoding', 'identity') != 'identity':
                        raise ClientError('INVALID_RESPONSE')
                    content = bytearray()
                    async for chunk in response.aiter_raw():
                        if len(content) + len(chunk) > MAX_JSON_BYTES:
                            raise ClientError('RESPONSE_TOO_LARGE')
                        content.extend(chunk)
                    value = decode_json(content)
                    if response.status_code != 200 or 'error' in value:
                        error = value.get('error')
                        code = error.get('code') if type(error) is dict else None
                        raise ClientError(code if isinstance(code, str) and code in SERVER_CODES
                                          else 'HTTP_ERROR', status=response.status_code)
                    return value
