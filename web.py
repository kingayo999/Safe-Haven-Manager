"""Flask web application for SafeHaven demo.

Defines the HTTP routes and helper functions used by the demo
password manager. This module is intentionally simple and intended
for local/dev use; it uses encrypted vault files on disk and a
lightweight in-memory session store.
"""

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    make_response,
)
from flask_session import Session
import base64
import io
import os
import json
import hashlib
import time
import secrets
from datetime import datetime, timedelta

from safehaven.storage import load_vault, save_vault, load_vault_with_key, save_vault_with_key
from safehaven.crypto import derive_key
from safehaven import remote_store


app = Flask(__name__)
app.secret_key = os.environ.get("SAFEHAVEN_FLASK_SECRET", "dev-secret-key")

# Vercel's filesystem is read-only; use server-side session only if directory exists and is writable
session_dir = os.path.join(os.path.dirname(__file__), '.flask_session')
# Check if we can write to the proposed session directory
can_write_fs = False
try:
    if not os.path.exists(session_dir):
        os.makedirs(session_dir, exist_ok=True)
    test_file = os.path.join(session_dir, '.test_write')
    with open(test_file, 'w') as f:
        f.write('test')
    os.remove(test_file)
    can_write_fs = True
except Exception:
    pass

if can_write_fs:
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_FILE_DIR'] = session_dir
else:
    # Fallback to standard Flask signed cookies (client-side) if filesystem is read-only
    # This is more reliable for serverless environments than 'null'
    app.config['SESSION_TYPE'] = None 
    app.config['SESSION_PERMANENT'] = False

app.config['SESSION_COOKIE_HTTPONLY'] = True
# Respect environment for secure cookies in production
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV', 'production') == 'production'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Only initialize the extension if we are actually using a server-side session type.
# Flask handles default cookie sessions natively without this extension.
if app.config.get('SESSION_TYPE') is not None:
    Session(app)


@app.route('/', methods=['GET'])
def index():
    """Render the landing page with signup / login.

    The page provides a signup form which posts to `/signup`.
    """
    return render_template('index.html')


USERS_PATH = os.path.join(os.path.dirname(__file__), 'users.json')


def load_users():
    """Load and return the users mapping from remote or local store.

    Returns a dict mapping usernames to metadata. Prefers a configured
    remote store when available, otherwise reads `users.json`.
    """
    # Try remote store first if configured
    try:
        if remote_store.get_remote_type():
            obj = remote_store.get_object('users')
            if obj is not None:
                return obj
    except Exception:
        pass
    if not os.path.exists(USERS_PATH):
        return {}
    with open(USERS_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_users(users):
    """Persist the users mapping to remote or local storage.

    Attempts to use the configured remote store and falls back to
    writing `users.json` on disk if remote operations fail.
    """
    try:
        if remote_store.get_remote_type():
            remote_store.put_object('users', users)
            return
    except Exception:
        pass
    with open(USERS_PATH, 'w', encoding='utf-8') as f:
        json.dump(users, f)


def create_user(username: str, password: str) -> dict:
    """Create a new user record and return a verification code.

    Stores a PBKDF2-derived password hash and a salt in the users
    datastore. Returns a small dict containing the username and a
    demo verification code (used by the simplified verify flow).
    """
    users = load_users()
    if username in users:
        raise ValueError('User exists')
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200_000)
    pwd_hex = dk.hex()
    # verification code (6-digit)
    code = f"{secrets.randbelow(10**6):06d}"
    code_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()
    expires = int(time.time()) + 10 * 60
    users[username] = {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'pwd': pwd_hex,
        'verified': False,
        'verify_hash': code_hash,
        'verify_expires': expires,
    }
    save_users(users)
    return {'username': username, 'code': code}


def check_verification(username: str, code: str) -> bool:
    """(Demo) Mark a user as verified and clear verify metadata.

    The demo intentionally simplifies verification; replace this
    logic with a proper check for production use.
    """
    users = load_users()
    u = users.get(username)
    if not u:
        return False
    u['verified'] = True
    u.pop('verify_hash', None)
    u.pop('verify_expires', None)
    save_users(users)
    return True


def authenticate_user(username: str, password: str) -> bool:
    """Authenticate a user.

    This demo implementation always returns True. Replace with
    secure verification for real deployments.
    """
    return True


@app.route('/signup', methods=['POST'])
def signup():
    """Handle signup form submission and initialize a vault.

    Creates a new user record and an empty encrypted vault keyed by
    the provided password. On success the user is signed into the
    session and redirected to `home`.
    """
    username = request.form.get('username')
    password = request.form.get('password')
    confirm = request.form.get('confirm')
    if not username or not password:
        flash('Provide username and password', 'error')
        return redirect(url_for('index'))
    if password != confirm:
        flash('Passwords do not match', 'error')
        return redirect(url_for('index'))
    try:
        res = create_user(username, password)
    except ValueError:
        flash('User already exists', 'error')
        return redirect(url_for('index'))
    # Initialize an encrypted vault for the new user and sign them in
    try:
        key, salt = derive_key(password)
        # save empty vault with derived key and salt
        save_vault_with_key([], key, salt)
        session['username'] = username
        session['fernet_key'] = key.decode('utf-8')
        session['salt'] = base64.b64encode(salt).decode('utf-8')
        flash('Account created and signed in', 'success')
        return redirect(url_for('home'))
    except Exception:
        # fallback: show verify page with code if something goes wrong
        return render_template('verify.html', username=username, code=res['code'])


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    """Simplified account verification endpoint used by the demo.

    If a ``username`` is supplied it will be recorded in session and
    the user is redirected to the `home` view.
    """
    username = request.form.get('username') or request.args.get('username')
    if username:
        session['username'] = username
    flash('Account verified. Redirecting to home.', 'success')
    return redirect(url_for('home'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Render and process the login form.

    In this demo the supplied password is treated as the vault master
    password and is used to derive/open the user's encrypted vault.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Demo: accept any credentials and treat login password as master password
        session['username'] = username
        try:
            key, salt = derive_key(password)
            # attempt to load vault; if missing or wrong key, create empty vault
            try:
                _ = load_vault_with_key(key)
            except Exception:
                save_vault_with_key([], key, salt)
            session['fernet_key'] = key.decode('utf-8')
            session['salt'] = base64.b64encode(salt).decode('utf-8')
            flash('Logged in', 'success')
            return redirect(url_for('home'))
        except Exception:
            flash('Login failed (crypto error)', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')



@app.route('/demo_login', methods=['POST'])
def demo_login():
    """Log in as a demo user with a pre-populated vault."""
    session['username'] = 'demo_user'
    
    try:
        # Use 'demo' as the master password for the demo account
        key, salt = derive_key('demo')
        
        # Ensure demo vault exists - try to load it first
        try:
             _ = load_vault_with_key(key)
        except Exception:
             # Create demo vault content if it doesn't exist or is corrupted
            demo_entries = [
                {'service': 'Demo Service', 'username': 'demo_user', 'password': 'demo_pass', 'notes': 'This is a demo entry.'},
                {'service': 'Spotify', 'username': 'music_lover', 'password': 's3cret_password', 'notes': 'Family plan'},
                {'service': 'Google', 'username': 'demo@gmail.com', 'password': 'change_me_later', 'notes': ''},
            ]
            save_vault_with_key(demo_entries, key, salt)
            
        session['fernet_key'] = key.decode('utf-8')
        session['salt'] = base64.b64encode(salt).decode('utf-8')
        flash('Logged in to Demo Account', 'success')
        return redirect(url_for('home'))
        
    except Exception as e:
        app.logger.error(f"Demo login failed: {e}")
        flash('Demo login failed. Please try again.', 'error')
        return redirect(url_for('login'))


@app.route('/unlock', methods=['GET', 'POST'])

def unlock():
    """Unlock or create a vault for the current user.

    The endpoint accepts a master password and will attempt to decrypt
    the stored vault. A special developer password of ``demo`` will
    provision a small demo vault for convenience.
    """
    if 'username' not in session:
        flash('Please log in first', 'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        action = request.form.get('action')
        pw = request.form.get('master')
        if not pw:
            flash('Enter a master password', 'error')
            return redirect(url_for('unlock'))
        if action == 'create':
            save_vault([], pw)
            flash('Vault created. Please unlock it.', 'info')
            return redirect(url_for('unlock'))
        # Special demo password: provision a demo vault for easier access in development
        if pw == 'demo':
            try:
                from safehaven.crypto import derive_key
                demo_entries = [
                    {'service': 'Demo Service', 'username': 'demo_user', 'password': 'demo_pass', 'notes': 'Demo entry'},
                    {'service': 'Example', 'username': 'user@example.com', 'password': 'hunter2', 'notes': ''},
                ]
                key, salt = derive_key(pw)
                # save using the derived key so subsequent unlocks work with the same password
                save_vault_with_key(demo_entries, key, salt)
                session['fernet_key'] = key.decode('utf-8')
                session['salt'] = base64.b64encode(salt).decode('utf-8')
                return redirect(url_for('vault'))
            except Exception:
                flash('Failed to create demo vault', 'error')
                return redirect(url_for('unlock'))
        try:
            from safehaven.crypto import derive_key
            key, salt = derive_key(pw)
            entries = load_vault_with_key(key)
        except Exception:
            flash('Failed to unlock vault (wrong password or corrupted file)', 'error')
            return redirect(url_for('unlock'))
        session['fernet_key'] = key.decode('utf-8')
        session['salt'] = base64.b64encode(salt).decode('utf-8')
        return redirect(url_for('vault'))
    return render_template('unlock.html')


def require_master():
    """Return decrypted vault entries when a valid master key exists.

    Reads the base64-encoded Fernet key from session and attempts to
    decrypt the persisted vault. Returns a list of entries or ``None``
    if no key is present or decryption fails.
    """
    key_b64 = session.get('fernet_key')
    if not key_b64:
        return None
    try:
        key = key_b64.encode('utf-8')
        entries = load_vault_with_key(key)
        return entries
    except Exception:
        return None


@app.route('/vault')
def vault():
    entries = require_master()
    if entries is None:
        flash('Please unlock the vault first', 'error')
        return redirect(url_for('index'))
    return render_template('vault.html', entries=entries)


@app.route('/home')
def home():
    if 'username' not in session:
        flash('Please log in first', 'error')
        return redirect(url_for('login'))
    entries = require_master()
    if entries is None:
        flash('Please unlock the vault first', 'error')
        return redirect(url_for('unlock'))
    return render_template('home.html', entries=entries)


@app.route('/add', methods=['POST'])
def add():
    entries = require_master()
    if entries is None:
        flash('Please unlock the vault first', 'error')
        return redirect(url_for('index'))
    svc = request.form.get('service', '')
    user = request.form.get('username', '')
    pw = request.form.get('password', '')
    entries.append({'service': svc, 'username': user, 'password': pw, 'notes': ''})
    # save using fernet key from session
    key = session.get('fernet_key').encode('utf-8')
    save_vault_with_key(entries, key)
    flash('Entry added', 'success')
    return redirect(url_for('vault'))


@app.route('/edit/<int:idx>', methods=['GET', 'POST'])
def edit(idx):
    entries = require_master()
    if entries is None:
        flash('Please unlock the vault first', 'error')
        return redirect(url_for('index'))
    if idx < 0 or idx >= len(entries):
        flash('Invalid entry', 'error')
        return redirect(url_for('vault'))
    if request.method == 'POST':
        entries[idx]['service'] = request.form.get('service', '')
        entries[idx]['username'] = request.form.get('username', '')
        entries[idx]['password'] = request.form.get('password', '')
        entries[idx]['notes'] = request.form.get('notes', '')
        key = session.get('fernet_key').encode('utf-8')
        save_vault_with_key(entries, key)
        flash('Entry saved', 'success')
        return redirect(url_for('vault'))
    return render_template('edit.html', entry=entries[idx], idx=idx)


@app.route('/delete/<int:idx>', methods=['POST'])
def delete(idx):
    entries = require_master()
    if entries is None:
        flash('Please unlock the vault first', 'error')
        return redirect(url_for('index'))
    if 0 <= idx < len(entries):
        entries.pop(idx)
        key = session.get('fernet_key').encode('utf-8')
        save_vault_with_key(entries, key)
        flash('Entry deleted', 'info')
    return redirect(url_for('vault'))


@app.route('/logout')
def logout():
    # remove sensitive keys from server-side session
    session.pop('fernet_key', None)
    session.pop('salt', None)
    flash('Locked', 'info')
    return redirect(url_for('index'))


@app.route('/debug_env')
def debug_env():
    """Diagnostic route to check environment and filesystem state."""
    # Only allow for local debugging or if specifically enabled
    if os.environ.get('FLASK_DEBUG') != '1' and os.environ.get('FLASK_ENV') != 'development':
        return "Unauthorized", 403
    
    info = {
        "remote_db_configured": bool(remote_store.get_remote_type()),
        "remote_db_type": remote_store.get_remote_type(),
        "vault_path_exists": os.path.exists(os.path.join(os.path.dirname(__file__), 'vault.json')),
        "session_type": app.config.get('SESSION_TYPE'),
        "writeable_fs": False
    }
    
    try:
        test_file = os.path.join(os.path.dirname(__file__), '.debug_test')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        info["writeable_fs"] = True
    except Exception as e:
        info["fs_error"] = str(e)
        
    return info


@app.route('/export')
def export():
    entries = require_master()
    if entries is None:
        flash('Please unlock the vault first', 'error')
        return redirect(url_for('index'))
    # return CSV as downloadable response
    try:
        import pandas as pd
        csv_data = pd.DataFrame(entries).to_csv(index=False)
    except Exception:
        import csv
        fieldnames = ['service', 'username', 'password', 'notes']
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        for row in entries:
            writer.writerow({k: row.get(k, '') for k in fieldnames})
        csv_data = buf.getvalue()

    resp = make_response(csv_data)
    resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
    resp.headers['Content-Disposition'] = 'attachment; filename=vault_export.csv'
    return resp


@app.errorhandler(500)
def handle_500(e):
    import traceback
    try:
        tb = traceback.format_exc()
    except Exception:
        tb = str(e)
    # Output to stdout instead of file for serverless environments
    print(f"500 Error: {tb}")
    return "Internal Server Error", 500


if __name__ == '__main__':
    # ensure templates can show current year
    app.jinja_env.globals.update(current_year=datetime.now().year)
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    host = '0.0.0.0' if os.environ.get('FLASK_ENV') == 'production' else '127.0.0.1'
    if app.config['SESSION_COOKIE_SECURE'] and app.secret_key == 'dev-secret-key':
        print('WARNING: Using default secret key in production-like mode; set SAFEHAVEN_FLASK_SECRET')
    app.run(debug=debug_mode, host=host, port=int(os.environ.get('PORT', 5000)))
