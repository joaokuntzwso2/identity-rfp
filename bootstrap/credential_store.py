"""Durable credentials for synthetic PoC accounts.

Credential generation must precede provisioning: failed bootstrap stages must
never replace passwords already committed to a WSO2 tenant user store.
"""
import json
from pathlib import Path
import secrets


def atomic_private_json(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    with temp.open('w', encoding='utf-8') as handle:
        handle.write(json.dumps(data, indent=2, ensure_ascii=False))
    temp.chmod(0o600)
    temp.replace(path)
    path.chmod(0o600)


def stable_user_passwords(roots: dict, manifest_path: Path, store_path: Path) -> dict:
    """Persist before SCIM POST; migrate from existing verified-run manifest.

    Never invent a new password for an existing account when one has already
    been persisted. The migration from a completed manifest enables one-time
    SCIM password synchronization after the original interrupted bootstrap.
    """
    state = json.loads(store_path.read_text()) if store_path.exists() else {'users': {}}
    if not isinstance(state, dict) or not isinstance(state.get('users'), dict):
        raise ValueError('Invalid PoC user credential store')
    previous = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    previous_users = previous.get('users', {})
    credentials = {}
    for root, spec in roots.items():
        for username, *_ in spec['people']:
            key = root + ':' + username
            previous_record = previous_users.get(key, {})
            if previous_record and (previous_record.get('root') != root or previous_record.get('username') != username):
                raise ValueError('Manifest identity mismatch for ' + key)
            password = state['users'].get(key) or previous_record.get('password')
            if not password:
                password = secrets.token_urlsafe(25) + 'aB7!'
            if not isinstance(password, str) or len(password) < 16:
                raise ValueError('Missing or weak credential for ' + key)
            state['users'][key] = password
            credentials[key] = password
    atomic_private_json(store_path, state)
    return credentials
