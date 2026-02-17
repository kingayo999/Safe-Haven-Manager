"""Tkinter desktop application for SafeHaven.

This module implements a simple desktop UI wrapper around the same
vault storage used by the web demo. It provides dialogs to create,
unlock, view, edit and export password entries.
"""

import os
import json
import secrets
import string
import webbrowser
import traceback
from tkinter import (
    Tk,
    Toplevel,
    Label,
    Entry,
    Button,
    Listbox,
    Scrollbar,
    END,
    SINGLE,
    messagebox,
    simpledialog,
)

HAS_NUMPY = HAS_PANDAS = HAS_MATPLOTLIB = HAS_SEABORN = HAS_PLOTLY = False
np = None
pd = None
plt = None
sns = None
px = None
pyo = None
FigureCanvasTkAgg = None
try:
    import numpy as np
    HAS_NUMPY = True
except Exception:
    np = None

try:
    import pandas as pd
    HAS_PANDAS = True
except Exception:
    pd = None

try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    HAS_MATPLOTLIB = True
except Exception:
    plt = None
    FigureCanvasTkAgg = None

try:
    import seaborn as sns
    HAS_SEABORN = True
except Exception:
    sns = None

try:
    import plotly.express as px
    import plotly.offline as pyo
    HAS_PLOTLY = True
except Exception:
    px = None
    pyo = None

from .storage import load_vault, save_vault


class SafeHavenApp:
    """Main Tkinter application class for the SafeHaven desktop UI.

    The class encapsulates UI state (master password and entries)
    and provides methods to build and control the various dialogs.
    """
    def __init__(self):
        self.master_password = None
        self.entries = []
        self.filtered_indices = []
        self.root = Tk()
        self.root.title("SafeHaven")
        self.root.geometry("600x400")
        self.root.lift()
        self.root.attributes('-topmost',True)
        self.root.after_idle(self.root.attributes,'-topmost',False)
        self.auto_lock_minutes = 5
        self._auto_lock_id = None
        self._build_login()

    def run(self):
        """Start the Tkinter main loop and show the application window."""
        self.root.mainloop()

    def _build_login(self):
        self.clear_root()
        Label(self.root, text="SafeHaven — Enter Master Password").pack(pady=10)
        self.pw_entry = Entry(self.root, show="*")
        self.pw_entry.pack(pady=5)
        Button(self.root, text="Unlock", command=self._unlock).pack(pady=5)
        Button(self.root, text="Create New Vault", command=self._create_vault).pack(pady=2)

    def _create_vault(self):
        """Prompt the user to create a new master password and save an empty vault."""
        pw1 = simpledialog.askstring("Create Master", "Enter new master password:", show="*")
        if not pw1:
            return
        pw2 = simpledialog.askstring("Confirm", "Confirm master password:", show="*")
        if pw1 != pw2:
            messagebox.showerror("Error", "Passwords do not match")
            return
        self.master_password = pw1
        self.entries = []
        save_vault(self.entries, self.master_password)
        messagebox.showinfo("Vault", "New vault created. Please unlock it.")

    def _unlock(self):
        """Attempt to decrypt and load the vault using the entered password."""
        pw = self.pw_entry.get()
        if not pw:
            messagebox.showerror("Error", "Please enter a password")
            return
        try:
            data = load_vault(pw)
        except Exception:
            messagebox.showerror("Error", "Failed to decrypt vault: wrong password or corrupted file")
            return
        self.master_password = pw
        self.entries = data
        self._build_main()

    def _build_main(self):
        """Construct the main vault view and control panels."""
        self.clear_root()
        Label(self.root, text="SafeHaven — Vault").pack()
        # Search box
        search_frame = Toplevel(self.root)
        search_frame.title("Search")
        search_frame.geometry("400x60")
        Label(search_frame, text="Search:").pack(side="left", padx=4)
        self.search_var = Entry(search_frame, width=50)
        self.search_var.pack(side="left", padx=4)
        self.search_var.bind("<KeyRelease>", lambda e: (self.reset_auto_lock(), self._on_search_change()))
        frame = self.root
        self.lb = Listbox(frame, selectmode=SINGLE, width=80)
        self.lb.pack(padx=10, pady=10, expand=True, fill="both")
        self._refresh_listbox()

        btn_frame = Toplevel(self.root)
        btn_frame.title("Controls")
        btn_frame.geometry("300x250")
        Button(btn_frame, text="Add Entry", command=self._add_entry).pack(fill="x", pady=3)
        Button(btn_frame, text="View Entry", command=lambda: (self.reset_auto_lock(), self._view_entry())).pack(fill="x", pady=3)
        Button(btn_frame, text="Edit Entry", command=lambda: (self.reset_auto_lock(), self._edit_entry())).pack(fill="x", pady=3)
        Button(btn_frame, text="Delete Entry", command=lambda: (self.reset_auto_lock(), self._delete_entry())).pack(fill="x", pady=3)
        Button(btn_frame, text="Generate Password", command=self._gen_password_dialog).pack(fill="x", pady=3)
        Button(btn_frame, text="Show Stats (Matplotlib)", command=self._show_stats_matplotlib).pack(fill="x", pady=3)
        Button(btn_frame, text="Show Stats (Plotly)", command=self._show_stats_plotly).pack(fill="x", pady=3)
        Button(btn_frame, text="Export CSV", command=self._export_csv).pack(fill="x", pady=3)
        Button(btn_frame, text="Auto-lock (minutes)", command=self._set_auto_lock_dialog).pack(fill="x", pady=3)
        Button(btn_frame, text="Lock", command=self._lock).pack(fill="x", pady=3)
        self.reset_auto_lock()

    def _refresh_listbox(self):
        self.lb.delete(0, END)
        query = self.search_var.get() if hasattr(self, "search_var") else ""
        self.filtered_indices = []
        for i, e in enumerate(self.entries):
            svc = e.get('service', '<no service>')
            user = e.get('username', '')
            display = f"{i+1}. {svc} — {user}"
            if not query or query.lower() in svc.lower() or query.lower() in user.lower() or query.lower() in e.get('notes','').lower():
                self.filtered_indices.append(i)
                self.lb.insert(END, display)

    def _on_search_change(self):
        self._refresh_listbox()

    def _add_entry(self):
        """Show a dialog to add a new vault entry and persist it."""
        dlg = Toplevel(self.root)
        dlg.title("Add Entry")
        Label(dlg, text="Service").pack()
        svc = Entry(dlg)
        svc.pack()
        Label(dlg, text="Username").pack()
        user = Entry(dlg)
        user.pack()
        Label(dlg, text="Password").pack()
        show_var = None
        try:
            from tkinter import BooleanVar, Checkbutton
            show_var = BooleanVar(value=False)
        except Exception:
            show_var = None
        if show_var is not None:
            pw = Entry(dlg, show="*")
            def _toggle_show():
                pw.config(show="" if show_var.get() else "*")
            cb = Checkbutton(dlg, text="Show password", variable=show_var, command=_toggle_show)
            cb.pack()
        else:
            pw = Entry(dlg)
        pw.pack()

        def do_add():
            entry = {
                "service": svc.get(),
                "username": user.get(),
                "password": pw.get(),
                "notes": "",
            }
            self.entries.append(entry)
            save_vault(self.entries, self.master_password)
            self._refresh_listbox()
            self.reset_auto_lock()
            dlg.destroy()

        Button(dlg, text="Add", command=do_add).pack(pady=5)
        Button(dlg, text="Generate", command=lambda: pw.insert(0, self._generate_password(16))).pack(pady=2)

    def _view_entry(self):
        """Display the selected entry in a modal info dialog."""
        sel = self.lb.curselection()
        if not sel:
            messagebox.showinfo("Info", "Select an entry first")
            return
        idx = sel[0]
        actual_idx = self.filtered_indices[idx]
        e = self.entries[actual_idx]
        info = json.dumps(e, indent=2)
        self.reset_auto_lock()
        messagebox.showinfo(f"Entry: {e.get('service')}", info)

    def _delete_entry(self):
        """Delete the selected entry after asking for confirmation."""
        sel = self.lb.curselection()
        if not sel:
            messagebox.showinfo("Info", "Select an entry first")
            return
        idx = sel[0]
        actual_idx = self.filtered_indices[idx]
        if messagebox.askyesno("Confirm", "Delete selected entry?"):
            self.entries.pop(actual_idx)
            save_vault(self.entries, self.master_password)
            self._refresh_listbox()
            self.reset_auto_lock()

    def _edit_entry(self):
        """Open a dialog to edit the selected entry and save changes."""
        sel = self.lb.curselection()
        if not sel:
            messagebox.showinfo("Info", "Select an entry first")
            return
        idx = sel[0]
        actual_idx = self.filtered_indices[idx]
        e = self.entries[actual_idx]
        dlg = Toplevel(self.root)
        dlg.title("Edit Entry")
        Label(dlg, text="Service").pack()
        svc = Entry(dlg)
        svc.insert(0, e.get("service", ""))
        svc.pack()
        Label(dlg, text="Username").pack()
        user = Entry(dlg)
        user.insert(0, e.get("username", ""))
        user.pack()
        Label(dlg, text="Password").pack()
        show_var = None
        try:
            from tkinter import BooleanVar, Checkbutton
            show_var = BooleanVar(value=False)
        except Exception:
            show_var = None
        if show_var is not None:
            pw = Entry(dlg, show="*")
            pw.insert(0, e.get("password", ""))
            def _toggle_show_edit():
                pw.config(show="" if show_var.get() else "*")
            cb = Checkbutton(dlg, text="Show password", variable=show_var, command=_toggle_show_edit)
            cb.pack()
        else:
            pw = Entry(dlg)
            pw.insert(0, e.get("password", ""))
        pw.pack()
        Label(dlg, text="Notes").pack()
        notes = Entry(dlg)
        notes.insert(0, e.get("notes", ""))
        notes.pack()

        def do_save():
            e["service"] = svc.get()
            e["username"] = user.get()
            e["password"] = pw.get()
            e["notes"] = notes.get()
            save_vault(self.entries, self.master_password)
            self._refresh_listbox()
            self.reset_auto_lock()
            dlg.destroy()

        Button(dlg, text="Save", command=do_save).pack(pady=5)

    def _gen_password_dialog(self):
        length = simpledialog.askinteger("Length", "Password length", initialvalue=16, minvalue=6, maxvalue=128)
        if not length:
            return
        pwd = self._generate_password(length)
        messagebox.showinfo("Generated Password", pwd)
        self.reset_auto_lock()

    def _generate_password(self, length=16):
        """Generate a random password using `secrets` and the given length."""
        alphabet = string.ascii_letters + string.digits + string.punctuation
        # Prefer secrets for cryptographic randomness
        return "".join(secrets.choice(alphabet) for _ in range(length))

    def _show_stats_matplotlib(self):
        if not self.entries:
            messagebox.showinfo("Stats", "No entries to analyze")
            return
        if not HAS_MATPLOTLIB:
            messagebox.showerror("Missing dependency", "Matplotlib is required for this feature. Install via 'pip install matplotlib'.")
            return
        lengths = [len(e.get("password", "")) for e in self.entries]
        if HAS_SEABORN:
            try:
                sns.set(style="darkgrid")
            except Exception:
                pass
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.hist(lengths, bins=range(0, max(lengths) + 2))
        ax.set_title("Password Length Distribution")
        ax.set_xlabel("Length")
        ax.set_ylabel("Count")

        if FigureCanvasTkAgg:
            win = Toplevel(self.root)
            win.title("Stats")
            canvas = FigureCanvasTkAgg(fig, master=win)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True)
        else:
            try:
                plt.show()
            except Exception:
                messagebox.showinfo("Stats", "Chart generated; install matplotlib/backends for embedding.")

    def _show_stats_plotly(self):
        if not self.entries:
            messagebox.showinfo("Stats", "No entries to analyze")
            return
        if not HAS_PLOTLY:
            messagebox.showerror("Missing dependency", "Plotly is required for this feature. Install via 'pip install plotly'.")
            return
        lengths = [len(e.get("password", "")) for e in self.entries]
        if not HAS_PANDAS:
            # build simple dataframe-like structure
            try:
                fig = px.histogram(x=lengths, nbins=max(lengths) if lengths else 1, title="Password Lengths")
                pyo.plot(fig, auto_open=True)
                self.reset_auto_lock()
                return
            except Exception:
                messagebox.showerror("Error", "Plotly/Plot generation failed.")
                return
        df = pd.DataFrame({"length": lengths})
        fig = px.histogram(df, x="length", nbins=max(lengths) if lengths else 1, title="Password Lengths")
        # open interactive chart in browser
        pyo.plot(fig, auto_open=True)
        self.reset_auto_lock()

    def _export_csv(self):
        """Export the current entries to a CSV file on disk."""
        if not self.entries:
            messagebox.showinfo("Export", "No entries to export")
            return
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vault_export.csv")
        if HAS_PANDAS:
            df = pd.DataFrame(self.entries)
            df.to_csv(path, index=False)
        else:
            # fallback using csv module
            import csv
            fieldnames = ["service", "username", "password", "notes"]
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for row in self.entries:
                    writer.writerow({k: row.get(k, "") for k in fieldnames})
        messagebox.showinfo("Exported", f"CSV exported to {path}")
        self.reset_auto_lock()

    def _lock(self):
        """Lock the application UI and clear sensitive state in memory."""
        self.master_password = None
        self.entries = []
        for w in self.root.winfo_children():
            try:
                w.destroy()
            except Exception:
                pass
        self._build_login()
        if self._auto_lock_id:
            try:
                self.root.after_cancel(self._auto_lock_id)
            except Exception:
                pass
            self._auto_lock_id = None

    def reset_auto_lock(self):
        # Cancel previous and restart auto-lock timer
        try:
            if self._auto_lock_id:
                self.root.after_cancel(self._auto_lock_id)
        except Exception:
            pass
        ms = max(1, int(self.auto_lock_minutes)) * 60 * 1000
        self._auto_lock_id = self.root.after(ms, self._lock)

    def _set_auto_lock_dialog(self):
        val = simpledialog.askinteger("Auto-lock", "Minutes until auto-lock:", initialvalue=self.auto_lock_minutes, minvalue=1, maxvalue=1440)
        if val:
            self.auto_lock_minutes = val
            self.reset_auto_lock()

    def clear_root(self):
        for w in self.root.winfo_children():
            try:
                w.destroy()
            except Exception:
                pass
