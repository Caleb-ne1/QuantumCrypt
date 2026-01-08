# QuantumCrypt v1.0 

**Folder & File Encryption**

QuantumCrypt is a secure encryption tool for files and folders, designed to:

* Encrypt/decrypt files or folders with AES-256-GCM
* Protect `.enc` files using OS immutability (optional)
* Automatically delete originals and decrypted `.enc` files
* Support **fast** and **normal** modes
* Provide an interactive CLI with progress bars and headers

---

## Table of Contents

1. [Features](#features)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Setup](#setup)
5. [Usage](#usage)

   * [Encrypting Files/Folders](#encrypting-filesfolders)
   * [Decrypting Files](#decrypting-files)
   * [Fast Mode](#fast-mode)
6. [Permissions](#permissions)
7. [Notes](#notes)
8. [License](#license)

---

## Features

* AES-256-GCM encryption for strong security
* SCRYPT KDF for password-based key derivation
* Folder or single file encryption
* Automatically deletes originals after encryption
* `.enc` files are deleted after decryption even if created with sudo
* Optional immutability (`chattr +i`) when run with sudo
* Interactive CLI with Rich progress bars
* Fast/normal modes for CPU performance trade-offs

---

## Requirements

* Python 3.10+
* packages:

```bash
sudo apt install python3-cryptography python3-rich
```

* Linux OS for immutability support (`chattr`)

---

## Installation

1. Clone the repository or copy `crypt` script to a directory:

```bash
git clone https://github.com/Caleb-ne1/QuantumCrypt.git
cd QuantumCrypt
```

2. Move to `/usr/local/bin` to run it globally:

```bash
sudo mv crypt.py /usr/local/bin/crypt
```

2. Make it executable:

```bash
sudo chmod +x /usr/local/bin/crypt
```

Now you can run the `crypt` command from anywhere.

---

## Setup

* No additional configuration required.
* Ensure `chattr` is installed for immutability support:

```bash
sudo apt install e2fsprogs   # Debian/Ubuntu
```

---

## Usage

### Encrypting Files/Folders

```bash
crypt <file or folder>
```

Example:

```bash
crypt myfolder
crypt photo.jpg
```

* Enter a **Quantum Key** when prompted.
* Confirm the key.
* The original file/folder is **deleted automatically**.
* The output `.enc` file is **immutable** if run with `sudo`, otherwise normal.

---

### Decrypting Files

```bash
crypt <encrypted_file>.enc
```

Example:

```bash
crypt myfolder.enc
crypt photo.jpg.enc
```

* Enter the **Quantum Key** used during encryption.
* The decrypted files/folders are restored.
* The `.enc` file is **always deleted** after decryption, even if it was immutable.

---

### Fast Mode

To speed up encryption/decryption (less CPU intensive, slightly lower security):

```bash
crypt myfolder --fast
crypt photo.jpg.enc --fast
```

---

## Permissions

* **Run with sudo** to enable immutability (`chattr +i`) on `.enc` files.
* **Without sudo**, `.enc` files are normal and will be deleted after decryption.

**Tip:** Immutable `.enc` files prevent accidental deletion by normal users but will **still be deleted** after decryption.

---

## Notes

* QuantumCrypt supports both **folders and single files**.
* Always remember your **Quantum Key**; losing it will permanently prevent decryption.
* Ensure enough disk space for temporary `.tar` archives during encryption/decryption.
* Designed for Linux; immutability commands (`chattr`) will not work on Windows/macOS.

---

