"""One durable allocation per approved Pi grant, independent of run directories.

The ledger is anchored beside the dedicated controller attestation key. Copying
an otherwise identical runtime record cannot mint another run-wide budget.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import time
from contextlib import contextmanager
from typing import Any

from .contracts import ContractError, canonical_json_bytes
from . import provider_receipts

SCHEMA = 'autofv-pi-grant-allocation/v1'
FIELDS = {'schema','approval_id','grant_sha256','runtime_record_sha256','run_config_sha256',
          'run_id','input_root','snapshot_sha256','initial_run_root','final_run_root','auth'}


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _path(record: dict[str, Any]) -> Path:
    parent = Path(record['receipt_signing_key_path']).resolve(strict=True).parent
    if parent.stat().st_uid != os.getuid() or stat.S_IMODE(parent.stat().st_mode) & 0o077:
        raise ContractError('Pi allocation authority directory must be private and owned')
    directory = parent / 'run-allocations'
    directory.mkdir(mode=0o700, exist_ok=True)
    status = directory.lstat()
    if (stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode)
        or status.st_uid != os.getuid() or stat.S_IMODE(status.st_mode) & 0o077):
        raise ContractError('Pi grant allocation directory is unsafe')
    return directory / (hashlib.sha256(record['grant']['approval_id'].encode()).hexdigest() + '.json')


@contextmanager
def _lock(path: Path, deadline_ms: int):
    fd = os.open(path.with_suffix('.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        status = os.fstat(fd)
        if (not stat.S_ISREG(status.st_mode) or status.st_nlink != 1 or status.st_uid != os.getuid()
            or stat.S_IMODE(status.st_mode) & 0o077):
            raise ContractError('Pi grant allocation lock is unsafe')
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.time_ns() // 1_000_000 >= deadline_ms:
                    raise ContractError('Pi original grant expired while waiting for allocation')
                time.sleep(.01)
        yield
    finally:
        os.close(fd)


def _read(path: Path, binding: Any) -> dict[str, Any] | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as stream:
        status = os.fstat(stream.fileno())
        if (not stat.S_ISREG(status.st_mode) or status.st_nlink != 1 or status.st_size > 32768
            or status.st_uid != os.getuid() or stat.S_IMODE(status.st_mode) & 0o077):
            raise ContractError('Pi grant allocation is unsafe')
        raw = stream.read(32769)
    try:
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != FIELDS or raw != canonical_json_bytes(value) + b'\n':
            raise ValueError('shape')
    except (ValueError, UnicodeError) as exc:
        raise ContractError('Pi grant allocation is malformed') from exc
    provider_receipts.verify_signature({k:v for k,v in value.items() if k != 'auth'},
        value['auth'], binding.public['receipt_authentication'], 'Pi grant allocation')
    if value['schema'] != SCHEMA:
        raise ContractError('Pi grant allocation schema mismatch')
    return value


def _write(path: Path, body: dict[str, Any], binding: Any) -> dict[str, Any]:
    value = {**body, 'auth': provider_receipts._sign(binding, body)}
    fd, name = tempfile.mkstemp(prefix='.allocation-', dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),0o600)
            stream.write(canonical_json_bytes(value)+b'\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name,path)
        directory = os.open(path.parent,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(name): os.unlink(name)
    return value


def claim(run: dict[str, Any], config: dict[str, Any], record: dict[str, Any], binding: Any) -> None:
    path = _path(record)
    fixed = {'schema':SCHEMA, 'approval_id':record['grant']['approval_id'],
        'grant_sha256':_sha(record['grant']), 'runtime_record_sha256':_sha(record),
        'run_config_sha256':_sha(config), 'run_id':run['run_id'],
        'input_root':str(Path(run['input_root']).resolve(strict=True)),
        'snapshot_sha256':run.get('snapshot_sha256')}
    root = str(Path(run['run_root']).resolve(strict=True))
    with _lock(path,record['grant']['original_deadline_epoch_ms']):
        existing = _read(path,binding)
        if existing is None:
            if run.get('provider_binding') is not None or run.get('pi_allocation_sha256') is not None:
                raise ContractError('Pi original grant allocation is missing on resume')
            value = _write(path,{**fixed,'initial_run_root':root,'final_run_root':None},binding)
        else:
            if any(existing.get(k) != v for k,v in fixed.items()):
                raise ContractError('Pi approval is already allocated to another run or identity')
            expected_root = existing['final_run_root'] or existing['initial_run_root']
            if root != expected_root:
                raise ContractError('Pi grant allocation run root changed')
            if run.get("pi_allocation_sha256") not in (None, _sha(existing)):
                raise ContractError("Pi remembered grant allocation changed")
            value = existing
    run['pi_allocation_sha256'] = _sha(value)
    run['runtime_record_sha256'] = fixed['runtime_record_sha256']


def finalize(run: dict[str, Any], record: dict[str, Any], binding: Any) -> None:
    """Pin the controller's one staging-to-final artifact-root transition."""
    path = _path(record)
    root = str(Path(run['run_root']).resolve(strict=True))
    with _lock(path,record['grant']['original_deadline_epoch_ms']):
        value = _read(path,binding)
        if value is None or value['run_id'] != run['run_id'] or value['runtime_record_sha256'] != _sha(record):
            raise ContractError('Pi grant allocation is missing or changed')
        if value['final_run_root'] is not None:
            if value['final_run_root'] != root:
                raise ContractError('Pi final run allocation cannot move again')
        else:
            body = {k:v for k,v in value.items() if k != 'auth'}
            body['final_run_root'] = root
            value = _write(path,body,binding)
    run['pi_allocation_sha256'] = _sha(value)


def verify(run: dict[str, Any], record: dict[str, Any], binding: Any) -> None:
    path = _path(record)
    with _lock(path,record['grant']['original_deadline_epoch_ms']):
        value = _read(path,binding)
        if (value is None or value['run_id'] != run['run_id']
            or value['runtime_record_sha256'] != _sha(record)
            or value['grant_sha256'] != _sha(record['grant'])
            or value['final_run_root'] != str(Path(run['run_root']).resolve(strict=True))
            or run.get('pi_allocation_sha256') != _sha(value)):
            raise ContractError('Pi run does not own its original grant allocation')
