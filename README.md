# SafeHaven 🛡️

SafeHaven is a powerful, secure password manager featuring both a sleek **Web Interface** and a robust **Desktop Application**. It uses state-of-the-art encryption (PBKDF2-HMAC-SHA256) to keep your credentials safe.

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fkingayo999%2FSafe-Haven-Manager)

## 🚀 Live Demo

Experience SafeHaven directly in your browser:
**[View Live Demo on Vercel](https://github.com/kingayo999/Safe-Haven-Manager)** *(Link your Vercel deployment here)*

---

## 🌐 Web Manager (Flask)

The web version provides a modern, responsive interface for managing your vault from any device.

### Quick Start (Web)
1. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
2. Run the application:
   ```powershell
   python web.py
   ```
3. Open [http://localhost:5000](http://localhost:5000)

### ☁️ Deployment from GitHub
SafeHaven is optimized for **Vercel**. Every push to the `main` branch will automatically trigger a redeploy if you link your GitHub repository to your Vercel project.

---

## 💻 Desktop App (Tkinter)

A standalone desktop version for secure, offline password management.

### Quick Start (Desktop)
```powershell
python main.py
```

---

## 🔒 Security & Features

- **End-to-End Encryption**: Master password protected vault encrypted with Fernet (PBKDF2-HMAC-SHA256 key derivation + per-vault salt).
- **Remote Persistence**: Supports **Supabase** and **Firebase** for cloud-syncing your encrypted vault.
- **Entry Management**: Add, View, Edit, and Delete entries with ease.
- **Password Generator**: Built-in strong password generator.
- **Analytics**: Interactive Plotly charts and Matplotlib histograms for vault insights.

## 🛠️ Configuration (Production)

To use remote storage and secure sessions, set the following environment variables:
- `SECUREPASS_DB`: `supabase` or `firebase`
- `SUPABASE_URL` / `SUPABASE_KEY`
- `FIREBASE_DB_URL`
- `SAFEHAVEN_FLASK_SECRET`: Your secret key for session encryption.

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
