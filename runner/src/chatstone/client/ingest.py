"""Separate collector write protocol; never a read-tool operation."""
import base64
import hashlib
from dataclasses import asdict
from time import monotonic
from uuid import UUID

from .transport import Client, ClientError, encode_json

MAX_INGEST_JSON_BYTES = 2_097_152


def encode_ingest_json(value):
    """Bound the complete write envelope at the ingest-only 2 MiB server limit.

    Preserve canonical bytes; read requests/responses keep their smaller bound.
    This is not the product's 25 MB per-message/file acceptance limit.
    """
    return encode_json(value, maximum=MAX_INGEST_JSON_BYTES)


def encode_spool_json(value):
    """Keep originals durable locally; only bounded metadata crosses JSON ingest."""
    def metadata(v):
        if isinstance(v, list):
            return [metadata(item) for item in v]
        if isinstance(v, dict):
            return {k: (None if k == 'data_base64' else metadata(item)) for k, item in v.items()}
        return v
    encode_ingest_json(metadata(value))
    return encode_json(value, maximum=100_000_000)


def encode_record(record):
    """Exact explicit JSON inverse of api.collector.decode_record.

    Inline raw/attachments are required by that API, not references to blobs.
    No fields, unknown roles, warnings or provenance are intentionally dropped.
    """
    value = asdict(record)
    value['raw_record_base64'] = base64.b64encode(value.pop('raw_record')).decode('ascii')
    value['message']['ts'] = record.message.ts.isoformat() if record.message.ts else None
    value['message']['parts'] = list(value['message']['parts'])
    value['message']['warnings'] = list(value['message']['warnings'])
    value['attachments'] = list(value['attachments'])
    for attachment in value['attachments']:
        data = attachment.pop('data')
        attachment['data_base64'] = base64.b64encode(data).decode('ascii') if data is not None else None
    return value


def _wire_record(value):
    """Escape NUL only in free text, never rewrite a durable record or identity.

    Verify original digests before conversion. The unchanged strict server
    retains structural validation for both converted and unchanged records.
    """
    if type(value) is not dict or type(value.get('message')) is not dict:
        return value
    original = value['message']
    message = dict(original)
    content = message.get('content')
    changed = type(content) is str and '\x00' in content
    if changed:
        message['content'] = content.replace('\x00', '\\u0000')
    if type(message.get('parts')) is list:
        parts = []
        for part in message['parts']:
            if type(part) is dict:
                part = dict(part)
                for key in ('text', 'arguments_json'):
                    text = part.get(key)
                    if type(text) is str and '\x00' in text:
                        part[key] = text.replace('\x00', '\\u0000')
                        changed = True
            parts.append(part)
        message['parts'] = parts
    if not changed:
        return value

    from chatstone.collectors.normalization import canonical

    try:
        semantic = canonical({key: original[key] for key in ('native_role', 'content', 'parts')})
        raw = base64.b64decode(value['raw_record_base64'], validate=True)
        if (hashlib.sha256(semantic).hexdigest() != original['content_hash']
                or hashlib.sha256(raw).hexdigest() != original['raw_hash']):
            raise ValueError
        if type(message['warnings']) is not list:
            raise ValueError
        message['warnings'] = list(message['warnings'])
        if 'TEXT_NUL_ESCAPED' not in message['warnings']:
            message['warnings'].append('TEXT_NUL_ESCAPED')
        semantic = canonical({key: message[key] for key in ('native_role', 'content', 'parts')})
        message['content_hash'] = hashlib.sha256(semantic).hexdigest()
        result = {**value, 'message': message}
        return result
    except (ValueError, KeyError, TypeError, OverflowError, RecursionError):
        raise ClientError('INVALID_REQUEST') from None


def identity(value):
    try:
        if type(value) is not str or str(UUID(value)) != value:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise ClientError('INVALID_REQUEST') from None
    return value


class IngestClient(Client):
    key_environment = 'CHATSTONE_INGEST_KEY'
    ordered = False  # Explicit orchestration opt-in after server upgrade.

    def _request(self, path, body, *, media='application/json', deadline=None, timeout=None):
        if not path.startswith('/api/v1/ingest/'):
            return super()._request(path, body, media=media, deadline=deadline, timeout=timeout)
        # 1 Mbit/s (125,000 bytes/s), 50% transmission margin + 15s setup.
        # Read APIs retain their own timeout. Explicit aggregate deadlines win.
        allowance = min(120, max(self.timeout, 15 + len(body) * 1.5 / 125_000))
        started = monotonic()
        try:
            return super()._request(path, body, media=media, deadline=deadline, timeout=allowance)
        except ClientError as error:
            error.upload_bytes = len(body)
            if ('/blobs/' in path and deadline is None and (
                    error.code in ('DEADLINE_EXCEEDED', 'REQUEST_TIMEOUT') or error.status == 408
                    or ((error.code == 'TRANSPORT_ERROR' or (error.status or 0) >= 500)
                        and monotonic()-started >= allowance-.5))):
                failure = ClientError('UPLOAD_BODY_TIMEOUT', status=error.status)
                failure.upload_bytes = len(body)
                raise failure from None
            raise

    def register_source(self, *, install_id, source, host, deadline=None):
        return self._request('/api/v1/ingest/sources', encode_json({
            'install_id': identity(install_id), 'source': source, 'host': host}), deadline=deadline)

    def update_sessions(self, *, install_id, sessions, deadline=None):
        return self._request('/api/v1/ingest/sessions', encode_json({
            'install_id': identity(install_id), 'sessions': sessions}), deadline=deadline)

    def _stage_attachments(self, install_id, records, deadline, *, staged=None):
        result = []
        for value in records:
            value = _wire_record(value)
            attachments = []
            for item in value['attachments']:
                encoded = item.get('data_base64')
                if encoded is not None:
                    try:
                        data = base64.b64decode(encoded, validate=True)
                    except ValueError:
                        raise ClientError('INVALID_REQUEST') from None
                    if len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
                        raise ClientError('INVALID_REQUEST')
                    if staged is None or item['sha256'] not in staged:
                        self.upload_blob(install_id=install_id, kind='attachments', data=data,
                                         deadline=deadline)
                        if staged is not None:
                            staged.add(item['sha256'])
                attachments.append({**item, 'data_base64': None})
            result.append({**value, 'attachments': attachments})
        return result

    def enqueue(self, *, install_id, batch_id, records, deadline=None):
        encode_spool_json({'records': records})
        records = self._stage_attachments(install_id, records, deadline)
        value = {'install_id': identity(install_id), 'batch_id': identity(batch_id), 'records': records}
        # Bound/validate the original encoding before allocating any converted text.
        body = encode_ingest_json(value)
        if type(records) is list:
            converted = [_wire_record(record) for record in records]
            if any(new is not old for new, old in zip(converted, records)):
                body = encode_ingest_json({**value, 'records': converted})
        return self._request('/api/v1/ingest/batches', body, deadline=deadline)

    def enqueue_ordered(self, *, batches, deadline=None):
        """Explicit fail-stop endpoint; each envelope keeps its durable identity."""
        encode_ingest_json({'batches': batches})  # Original complete bound before conversion.
        converted = []
        for batch in batches:
            converted.append({'install_id': identity(batch['install_id']),
                              'batch_id': identity(batch['batch_id']),
                              'records': self._stage_attachments(batch['install_id'], batch['records'], deadline)})
        return self._request('/api/v1/ingest/ordered',
                             encode_ingest_json({'batches': converted}), deadline=deadline)

    def upload_blob(self, *, install_id, kind, data, deadline=None):
        if kind not in ('raw', 'attachments') or type(data) is not bytes:
            raise ClientError('INVALID_REQUEST')
        if len(data) > 25000000:
            raise ClientError('REQUEST_TOO_LARGE')
        digest = hashlib.sha256(data).hexdigest()
        return self._request(f'/api/v1/ingest/blobs/{identity(install_id)}/{kind}/{digest}',
                             data, media='application/octet-stream', deadline=deadline)
