import os
import json
import base64
import hashlib
import secrets

from safehaven.crypto import derive_key
from safehaven.storage import save_vault_with_key


USERS_PATH = os.path.join(os.path.dirname(__file__), 'users.json')


def create_demo_user(username: str, password: str):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200_000)
    pwd_hex = dk.hex()
    users = {}
    if os.path.exists(USERS_PATH):
        try:
            with open(USERS_PATH, 'r', encoding='utf-8') as f:
                users = json.load(f)
        except Exception:
            users = {}
    users[username] = {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'pwd': pwd_hex,
        'verified': True,
    }
    with open(USERS_PATH, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=2)
    print(f'Wrote demo user to {USERS_PATH}')


def create_demo_vault(master_password: str):
    # sample entries
    entries = [
        {'service': 'Example', 'username': 'demo_user', 'password': 'P@ssw0rd!', 'notes': 'Demo entry'},
        {'service': 'Email', 'username': 'demo@example.com', 'password': 'emailpass', 'notes': ''},
    ]
    key, salt = derive_key(master_password)
    save_vault_with_key(entries, key, salt)
    print('Created encrypted demo vault (vault.json)')


if __name__ == '__main__':
    demo_user = os.environ.get('DEMO_USER', 'demo')
    demo_pass = os.environ.get('DEMO_PASS', 'demo')
    create_demo_user(demo_user, demo_pass)
    create_demo_vault(demo_pass)
    print('Demo DB initialization complete. Login with:', demo_user, demo_pass)
