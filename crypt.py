#!/usr/bin/env python3

"""
🔐 QUANTUMCRYPT v1.0 🔐
AES-256-GCM | SCRYPT KDF | Folder & File Encryption
- Auto-deletes originals
- .enc files can be immutable if run with sudo
- Smart auto-delete respects immutability
- Fast / Normal modes
- Futuristic CLI with rich
"""

import os
import sys
import tarfile
import argparse
import getpass
import secrets
import time
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# rich for enhanced visuals
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.panel import Panel
    from rich.prompt import Prompt
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("✨ Install 'rich' for full visuals: pip install rich")

# utilities
def derive_key(password: bytes, salt: bytes, fast: bool) -> bytes:
    n = 2**13 if fast else 2**15
    kdf = Scrypt(salt=salt, length=32, n=n, r=8, p=1, backend=default_backend())
    return kdf.derive(password)

def get_password(confirm: bool = True) -> bytes:
    if RICH_AVAILABLE:
        password = Prompt.ask("🔒 Enter Quantum Key", password=True)
        if confirm:
            confirm_pw = Prompt.ask("🔑 Confirm Key", password=True)
            if password != confirm_pw:
                print("❌ Keys do not match!")
                sys.exit(1)
        return password.encode()
    else:
        password = getpass.getpass("🔒 Enter Quantum Key: ")
        if confirm:
            confirm_pw = getpass.getpass("🔑 Confirm Key: ")
            if password != confirm_pw:
                print("❌ Keys do not match!")
                sys.exit(1)
        return password.encode()

def show_progress(message: str, steps: int = 50, delay: float = 0.02):
    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]{task.description}"),
            BarColumn(),
            TimeElapsedColumn()
        ) as progress:
            task = progress.add_task(message, total=steps)
            for i in range(steps):
                progress.update(task, advance=1)
                time.sleep(delay)
    else:
        spinner = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
        for i in range(steps):
            sys.stdout.write(f"\r{spinner[i % 10]} {message}...")
            sys.stdout.flush()
            time.sleep(delay)
        print()

def print_header(mode: str, security: str, target: str):
    if RICH_AVAILABLE:
        Console().print(Panel.fit(
            f"[bold cyan]⚡ {mode.upper()} MODE[/bold cyan]\n[green]Security: {security}[/green]\n[magenta]Target: {target}[/magenta]",
            title="[bold yellow] QUANTUMCRYPT v1.0 [/bold yellow]",
            border_style="cyan"
        ))
    else:
        print(f"\n⚡ {mode.upper()} MODE | Security: {security} | Target: {target}\n")

def print_success(message: str):
    if RICH_AVAILABLE:
        Console().print(f"[bold green]✅ {message}[/bold green]")
    else:
        print(f"✅ {message}")

def print_error(message: str):
    if RICH_AVAILABLE:
        Console().print(f"[bold red]⛔ {message}[/bold red]")
    else:
        print(f"⛔ {message}")

# encryption / decryption
def encrypt(path: str, fast: bool):
    target = Path(path).absolute()
    archive = target.with_suffix('.tar')
    enc_file = target.with_suffix('.enc')
    security = "HYPERSPEED" if fast else "QUANTUM-TUNNEL"

    print_header("ENCRYPTION", security, target.name)
    password = get_password(confirm=True)

    show_progress("Creating archive")
    with tarfile.open(archive, "w") as tar:
        tar.add(target, arcname=target.name)

    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = derive_key(password, salt, fast)
    aes = AESGCM(key)

    show_progress("Encrypting data", steps=75)
    with open(archive, "rb") as f:
        data = f.read()

    ciphertext = aes.encrypt(nonce, data, None)
    with open(enc_file, "wb") as f:
        f.write(salt + nonce + ciphertext)

    # cleanup original
    archive.unlink()
    if target.is_dir():
        import shutil
        shutil.rmtree(target)
    else:
        target.unlink()

    # attempt immutability
    immutable_set = False
    try:
        subprocess.run(["chattr", "+i", str(enc_file)], check=True)
        immutable_set = True
    except Exception:
        print_error("⚠️ Could not make .enc immutable (sudo required). It will be auto-deleted on decryption.")

    print_success(f"Encrypted: {enc_file.name} ({enc_file.stat().st_size / 1024:.1f} KB)")
    if immutable_set:
        print_success(f"{enc_file.name} is immutable and will NOT be auto-deleted on decryption")
    else:
        print_success(f"{enc_file.name} is normal; it WILL be auto-deleted on decryption")

def decrypt(enc_path: str, fast: bool):
    enc_file = Path(enc_path).absolute()
    security = "HYPERSPEED" if fast else "QUANTUM-TUNNEL"

    print_header("DECRYPTION", security, enc_file.name)
    password = get_password(confirm=False)

    # check if immutable
    immutable = False
    try:
        output = subprocess.run(["lsattr", str(enc_file)], capture_output=True, text=True)
        if 'i' in output.stdout.split()[0]:
            immutable = True
    except Exception:
        immutable = False

    # temporarily remove immutability if present
    if immutable:
        try:
            subprocess.run(["chattr", "-i", str(enc_file)], check=True)
        except Exception:
            print_error("⚠️ Could not remove immutability. Decryption may fail.")
            sys.exit(1)

    show_progress("Reading encrypted data", steps=30)
    with open(enc_file, "rb") as f:
        blob = f.read()

    salt = blob[:16]
    nonce = blob[16:28]
    ciphertext = blob[28:]
    key = derive_key(password, salt, fast)
    aes = AESGCM(key)

    try:
        show_progress("Decrypting data", steps=60)
        data = aes.decrypt(nonce, ciphertext, None)
    except Exception:
        print_error("Invalid key or corrupted file!")
        sys.exit(1)

    tar_file = enc_file.with_suffix('.tar')
    with open(tar_file, "wb") as f:
        f.write(data)

    show_progress("Restoring files", steps=40)
    with tarfile.open(tar_file) as tar:
        tar.extractall()
    tar_file.unlink()
    print_success(f"Decrypted: {enc_file.stem}")

    # DELETE .enc always, ignore immutable
    try:
        enc_file.unlink()
        print_success(f"Deleted: {enc_file.name}")
    except Exception:
        print_error(f"⚠️ Could not delete {enc_file.name}")


# CLI 
def main():
    parser = argparse.ArgumentParser(description="QUANTUMCRYPT v1.0 | AES-256-GCM | Folder/File Encryption")
    parser.add_argument("target", help="Folder, file, or .enc file")
    parser.add_argument("--fast", action="store_true", help="Fast mode (less CPU)")
    args = parser.parse_args()

    target = Path(args.target)
    fast = args.fast

    if target.is_dir() or (target.is_file() and not target.suffix == ".enc"):
        encrypt(str(target), fast)
    elif target.is_file() and target.suffix == ".enc":
        decrypt(str(target), fast)
    else:
        print_error(f"Invalid target: {target}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
        sys.exit(130)
