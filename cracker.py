import subprocess
import sys

# Auto-install bcrypt if not present
try:
    import bcrypt
except ImportError:
    print("[*] Installing required library: bcrypt...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "bcrypt"])
    print("[*] Restarting script...")
    subprocess.check_call([sys.executable] + sys.argv)
    sys.exit()

import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import threading
import hashlib
import bcrypt

found = False

# ---------- Clean input ----------
def clean_line(line):
    return line.strip().replace('\r', '').replace('\n', '')

# ---------- Auto hash detection ----------
def identify_hash(hash_str):
    if hash_str.startswith("$2a$") or hash_str.startswith("$2b$") or hash_str.startswith("$2y$"):
        return "bcrypt"
    elif len(hash_str) == 32:
        return "md5"
    elif len(hash_str) == 40:
        return "sha1"
    elif len(hash_str) == 56:
        return "sha224"
    elif len(hash_str) == 64:
        return "sha256"
    elif len(hash_str) == 96:
        return "sha384"
    elif len(hash_str) == 128:
        return "sha512"
    else:
        return "unknown"

# ---------- Log in GUI ----------
def log(msg):
    output_text.insert(tk.END, msg + '\n')
    output_text.see(tk.END)

# ---------- Get hash ----------
def get_hash(word, algorithm, target_hash):
    try:
        if algorithm == 'md5':
            return hashlib.md5(word.encode()).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(word.encode()).hexdigest()
        elif algorithm == 'sha224':
            return hashlib.sha224(word.encode()).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(word.encode()).hexdigest()
        elif algorithm == 'sha384':
            return hashlib.sha384(word.encode()).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(word.encode()).hexdigest()
        elif algorithm == 'bcrypt':
            return bcrypt.checkpw(word.encode(), target_hash.encode())
        else:
            return None
    except:
        return None

# ---------- Brute check ----------
def check_passwords(wordlist, target_hash, algorithm):
    global found
    found = False

    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                if found:
                    break
                word = clean_line(line)
                if not word:
                    continue

                result = get_hash(word, algorithm, target_hash)

                log(f"Trying: {word}")
                if algorithm == 'bcrypt':
                    if result:
                        found = True
                        log(f"\n[+] Password found: {word}")
                        return
                else:
                    if result == target_hash:
                        found = True
                        log(f"\n[+] Password found: {word}")
                        return

        if not found:
            log("[-] Password not found in wordlist.")

    except Exception as e:
        log(f"[!] Error: {e}")

# ---------- Start Button ----------
def start_cracking():
    target_hash = hash_entry.get().strip()
    algorithm = algo_var.get().strip().lower()
    wordlist = wordlist_entry.get()

    if not target_hash or not wordlist:
        messagebox.showerror("Missing Input", "Hash and Wordlist are required.")
        return

    if algorithm == "auto":
        algorithm = identify_hash(target_hash)
        algo_var.set(algorithm)
        log(f"[?] Auto-identified algorithm: {algorithm}")

    output_text.delete(1.0, tk.END)
    t = threading.Thread(target=check_passwords, args=(wordlist, target_hash, algorithm))
    t.start()

# ---------- Browse Wordlist ----------
def browse_wordlist():
    path = filedialog.askopenfilename(title="Select Wordlist", filetypes=[("Text files", "*.txt")])
    if path:
        wordlist_entry.delete(0, tk.END)
        wordlist_entry.insert(0, path)

# ---------- GUI ----------
app = tk.Tk()
app.title("Rex Password Cracker - GUI (bcrypt + md5/sha*)")
app.geometry("620x440")
app.resizable(False, False)

tk.Label(app, text="Hash to Crack:").pack(pady=5)
hash_entry = tk.Entry(app, width=80)
hash_entry.pack()

tk.Label(app, text="Algorithm:").pack(pady=5)
algo_var = tk.StringVar(value="auto")
algo_menu = tk.OptionMenu(app, algo_var, "auto", "bcrypt", "md5", "sha1", "sha224", "sha256", "sha384", "sha512")
algo_menu.pack()

tk.Label(app, text="Wordlist File:").pack(pady=5)
file_frame = tk.Frame(app)
file_frame.pack()
wordlist_entry = tk.Entry(file_frame, width=50)
wordlist_entry.pack(side=tk.LEFT)
browse_btn = tk.Button(file_frame, text="Browse", command=browse_wordlist)
browse_btn.pack(side=tk.LEFT, padx=5)

start_btn = tk.Button(app, text="Start Cracking", command=start_cracking, bg="green", fg="white", font=("Arial", 10, "bold"))
start_btn.pack(pady=10)

output_text = scrolledtext.ScrolledText(app, width=75, height=12, font=("Consolas", 10))
output_text.pack()

app.mainloop()
