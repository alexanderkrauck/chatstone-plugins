"""Explicit collector JSON to dataclasses; no Python object deserialization.

Hashes prove consistency, not trust in a caller's claims. Ingest SQL still
checks tenant/key/source scope. Every record is decoded before staging begins.
"""
import base64
import hashlib
import math
import re
from dataclasses import asdict, fields
from datetime import datetime

from chatstone.collectors.contracts import Attachment, NormalizedMessage, ParsedRecord, Part
from chatstone.collectors.normalization import canonical


class RequestError(ValueError):
    def __init__(self, code="INVALID_REQUEST"):
        self.code = code
        super().__init__(code)


def validate_tree(value, max_depth=16):
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > max_depth:
            raise RequestError()
        if isinstance(item, str):
            if "\x00" in item:
                raise RequestError()
            item.encode("utf-8")
        elif type(item) is float and not math.isfinite(item):
            raise RequestError()
        elif isinstance(item, dict):
            stack.extend((v, depth + 1) for pair in item.items() for v in pair)
        elif isinstance(item, list):
            stack.extend((v, depth + 1) for v in item)


HASH = re.compile('[0-9a-f]{64}')


def object_fields(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        raise RequestError()
    return dict(value)


def text(value, maximum, *, empty=False, nullable=False):
    if value is None and nullable:
        return value
    if (type(value) is not str or (not empty and not value)
            or '\x00' in value or len(value.encode('utf-8')) > maximum):
        raise RequestError()
    return value


def integer(value, maximum=2**63 - 1):
    if type(value) is not int or not 0 <= value <= maximum:
        raise RequestError()
    return value


def digest(value):
    if type(value) is not str or not HASH.fullmatch(value):
        raise RequestError()
    return value


def array(value, maximum):
    if type(value) is not list or len(value) > maximum:
        raise RequestError()
    return value


def binary(value):
    text(value, 33333336, empty=True)
    data = base64.b64decode(value, validate=True)
    if len(data) > 25000000 or base64.b64encode(data).decode() != value:
        raise RequestError()
    return data


def part(value):
    value = object_fields(value, (f.name for f in fields(Part)))
    if value['kind'] not in ('tool_call', 'tool_result', 'reasoning', 'attachment', 'oversize', 'invalid'):
        raise RequestError()
    for key in ('text', 'call_id', 'name', 'arguments_json', 'content_type'):
        text(value[key], 25000000 if key in ('text', 'arguments_json') else 4096,
             empty=True, nullable=True)
    if value['sha256'] is not None:
        digest(value['sha256'])
    if value['size'] is not None:
        integer(value['size'])
    return Part(**value)


def attachment(value):
    value = object_fields(value, ('sha256', 'size', 'content_type', 'oversize', 'data_base64'))
    digest(value['sha256'])
    integer(value['size'])
    text(value['content_type'], 256)
    if type(value['oversize']) is not bool:
        raise RequestError()
    encoded = value.pop('data_base64')
    if value['oversize']:
        if encoded is not None:
            raise RequestError()
        data = None
    else:
        data = None if encoded is None else binary(encoded)
        if value['size'] > 25000000:
            raise RequestError()
        if data is not None and (len(data) != value['size']
                                or hashlib.sha256(data).hexdigest() != value['sha256']):
            raise RequestError()
    return Attachment(**value, data=data)


def decode_record(value):
    try:
        validate_tree(value)
        value = object_fields(value, ('message', 'attachments', 'raw_record_base64'))
        message = object_fields(value['message'], (f.name for f in fields(NormalizedMessage)))
        for key, cap in [('source', 128), ('host_id', 256), ('native_session_id', 4096),
                         ('native_id', 4096)]:
            text(message[key], cap)
        integer(message['seq'])
        if message['role'] not in ('user', 'assistant', 'tool', 'system', None):
            raise RequestError()
        for key in ('native_role', 'native_source'):
            text(message[key], 4096, empty=True, nullable=True)
        text(message['content'], 25000000, empty=True)
        for key in ('raw_hash', 'content_hash'):
            digest(message[key])
        if message['ts'] is not None:
            text(message['ts'], 64)
            message['ts'] = datetime.fromisoformat(message['ts'])
            if message['ts'].utcoffset() is None:
                raise RequestError()
        message['parts'] = tuple(part(p) for p in array(message['parts'], 1000))
        message['warnings'] = tuple(text(w, 128) for w in array(message['warnings'], 100))
        attachments = tuple(attachment(a) for a in array(value['attachments'], 100))
        raw = binary(value['raw_record_base64'])
        semantic = canonical({'native_role': message['native_role'], 'content': message['content'],
                              'parts': [asdict(p) for p in message['parts']]})
        if (hashlib.sha256(raw).hexdigest() != message['raw_hash']
                or hashlib.sha256(semantic).hexdigest() != message['content_hash']):
            raise RequestError()
        return ParsedRecord(message=NormalizedMessage(**message), attachments=attachments,
                            raw_record=raw)
    except (ValueError, KeyError, TypeError, OverflowError, RecursionError):
        raise RequestError() from None
