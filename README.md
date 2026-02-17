# SafeHaven

SafeHaven is a desktop password manager (Tkinter) that stores an encrypted JSON vault.

Quick start

Install dependencies and run:

```powershell
pip install -r requirements.txt
python main.py
```

Main features

- Master password protected vault encrypted with Fernet (PBKDF2-HMAC-SHA256 key derivation + per-vault salt).
- Create / Unlock vault, Add / View / Edit / Delete entries (service, username, password, notes).
- Search/filter entries in the vault.
- Strong password generator.
- Auto-lock timer (configurable minutes).
- Export vault to CSV (uses pandas if available, falls back to csv module).
- Simple analytics: embedded Matplotlib histogram (if installed) and interactive Plotly chart (opens in browser).

Security notes

- The master password is used to derive an encryption key with PBKDF2 (200k iterations) and a random 16-byte salt stored alongside the vault.
- If the vault was created with the older SHA-256 key method, the app will attempt legacy decryption and transparently upgrade the vault to PBKDF2+salt when you unlock it successfully.
- Keep backups of `vault.json` (in the workspace root) and protect your master password — losing it will prevent decryption.

Missing dependencies

- The app provides graceful fallbacks and informative messages when optional packages (NumPy, Pandas, Matplotlib, Seaborn, Plotly, cryptography) are not installed. Install the full set for best experience:

```powershell
pip install numpy pandas matplotlib seaborn plotly cryptography
```

Files

- `main.py` — application entrypoint.
- `safehaven/crypto.py` — key derivation and (Fernet) encryption helpers.
- `safehaven/storage.py` — encrypted JSON vault save/load and upgrade path.
- `safehaven/app.py` — Tkinter GUI, search, edit, auto-lock, plotting and export features.

Next steps

- Run the app and test unlocking/creating a vault.
- I can run the app locally here to smoke-test it, or add features like secure clipboard clearing, sync, or edit history — tell me which you prefer.

Web mode

You can run a simple browser-accessible version using Flask:

```powershell
python web.py
# then open http://localhost:5000 in your browser
```

This web demo uses the same encrypted `vault.json` and reuses the storage/crypto code; it stores the master password temporarily in the Flask session for convenience (not recommended for production without secure server-side session management).

Professional presentation

- Clean responsive UI using Bootstrap with a custom theme and simple logo.
- Server-side sessions for the web demo (`Flask-Session`).
- Clear security section describing encryption, PBKDF2 parameters, and upgrade path from legacy SHA-256.
- Included templates, static assets, and instructions to run the web demo — suitable for a portfolio demo.

Polish / Next steps (suggested for portfolio)

- Add unit tests and CI pipeline (GitHub Actions) to demonstrate engineering rigour.
- Add automated security tests, static code analysis, and dependency checks.
- Replace demo verification code display with email/SMS in a real deployment.

Repository quality additions included

- Basic unit tests (`tests/`) for `crypto` and `storage` and a CI workflow at `.github/workflows/ci.yml`.
- `.gitignore` excludes secret and build artifacts.
- License and polished static assets (logo, favicon, CSS) included.
