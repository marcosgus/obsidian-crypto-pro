# Crypto Pro: Secure AES-GCM Encryption for Obsidian 🔒

A modern encryption plugin designed to protect sensitive information within your notes using industrial-grade cryptography standards.

---

## ✨ Key Features

* **AES-GCM (256-bit) Encryption**: Provides both confidentiality and integrity (Authenticated Encryption).
* **Secure Password Input**: Masked text fields to prevent the key from being visible while typing.
* **Two-Factor Validation**: Password confirmation when encrypting to prevent typing errors and data loss.
* **Native Integration**: Works through Obsidian commands and allows for custom Hotkey assignment.

## 🚀 Getting Started

1.  **Select** the text you want to protect.
2.  **Run** the command `Crypto Pro: Encrypt selected text`.
3.  To **recover** the content, select the encrypted block and run `Crypto Pro: Decrypt selected text`.

## 🛠️ Manual Installation

1.  **Download** `main.js`, `manifest.json`, and `styles.css` from the [Releases](https://github.com/marcosgus/obsidian-crypto-pro/releases) section.
2.  **Create a folder** named `obsidian-crypto-pro` in `.obsidian/plugins/` within your vault.
3.  **Copy the files** into that folder and enable the plugin in the Obsidian settings.

---

> [!TIP]
> **Pro Tip:** You can use the "lock" icon in the left ribbon to quickly encrypt or decrypt selections with smart auto-detection.

---
*Developed by Gus*