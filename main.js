"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const obsidian_1 = require("obsidian");
class CryptoPlugin extends obsidian_1.Plugin {
    lastPasswordUsed = null;
    async onload() {
        // 1. Icono inteligente en la barra lateral
        const ribbonIconEl = this.addRibbonIcon('lock', 'Crypto Pro: Auto-Acción', async () => {
            const view = this.app.workspace.getActiveViewOfType(obsidian_1.MarkdownView);
            if (!view) {
                new obsidian_1.Notice('❌ Abre una nota primero');
                return;
            }
            const editor = view.editor;
            const selection = editor.getSelection();
            if (!selection) {
                new obsidian_1.Notice('⚠️ Selecciona el texto para cifrar o descifrar');
                return;
            }
            const isEncrypted = selection.startsWith('%%ENC:') && selection.endsWith('%%');
            if (isEncrypted) {
                const data = selection.substring(6, selection.length - 2);
                new PasswordModal(this.app, "Descifrar", async (pass) => {
                    try {
                        const decrypted = await this.decrypt(data, pass);
                        editor.replaceSelection(decrypted);
                        this.lastPasswordUsed = pass;
                        new obsidian_1.Notice('🔓 Texto descifrado');
                    }
                    catch (e) {
                        new obsidian_1.Notice('❌ Contraseña incorrecta');
                    }
                }).open();
            }
            else {
                new PasswordModal(this.app, "Cifrar", async (pass) => {
                    const encrypted = await this.encrypt(selection, pass);
                    editor.replaceSelection(`%%ENC:${encrypted}%%`);
                    this.lastPasswordUsed = pass;
                    new obsidian_1.Notice('🔒 Texto cifrado');
                }).open();
            }
        });
        // 2. Auto-lock al cambiar de nota
        this.registerEvent(this.app.workspace.on('active-leaf-change', () => {
            this.lastPasswordUsed = null;
        }));
        // 3. Comando para la paleta
        this.addCommand({
            id: 'crypto-auto-action',
            name: 'Ejecutar Cifrado/Descifrado inteligente',
            callback: () => {
                const view = this.app.workspace.getActiveViewOfType(obsidian_1.MarkdownView);
                if (view)
                    ribbonIconEl.click();
            }
        });
    }
    async encrypt(text, password) {
        const encoder = new TextEncoder();
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const key = await this.deriveKey(password, salt);
        const encrypted = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(text));
        const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
        result.set(salt, 0);
        result.set(iv, salt.length);
        result.set(new Uint8Array(encrypted), salt.length + iv.length);
        return btoa(String.fromCharCode(...result));
    }
    async decrypt(base64Data, password) {
        const data = Uint8Array.from(atob(base64Data), c => c.charCodeAt(0));
        const salt = data.slice(0, 16);
        const iv = data.slice(16, 28);
        const encrypted = data.slice(28);
        const key = await this.deriveKey(password, salt);
        const decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);
        return new TextDecoder().decode(decrypted);
    }
    // --- CORRECCIÓN DE ERROR TS2322 ---
    async deriveKey(password, salt) {
        const encoder = new TextEncoder();
        const baseKey = await window.crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
        return window.crypto.subtle.deriveKey({
            name: "PBKDF2",
            salt: salt.buffer, // USAR .buffer PARA SOLUCIONAR EL ERROR
            iterations: 100000,
            hash: "SHA-256"
        }, baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    }
}
exports.default = CryptoPlugin;
class PasswordModal extends obsidian_1.Modal {
    action;
    onSubmit;
    constructor(app, action, onSubmit) {
        super(app);
        this.action = action;
        this.onSubmit = onSubmit;
    }
    onOpen() {
        const { contentEl } = this;
        contentEl.createEl("h2", { text: `${this.action} contenido` });
        let pass = "";
        let confirmPass = "";
        const handleAction = () => {
            if (this.action === "Cifrar" && pass !== confirmPass) {
                new obsidian_1.Notice("❌ Las contraseñas no coinciden.");
                return;
            }
            if (pass.length === 0) {
                new obsidian_1.Notice("⚠️ Vacía.");
                return;
            }
            this.close();
            this.onSubmit(pass);
        };
        new obsidian_1.Setting(contentEl).setName("Contraseña").addText(text => {
            text.inputEl.type = "password";
            text.setPlaceholder("Introduce tu clave...").onChange(value => pass = value);
            text.inputEl.addEventListener('keypress', (e) => { if (e.key === 'Enter' && this.action === "Descifrar")
                handleAction(); });
            setTimeout(() => text.inputEl.focus(), 50); // Auto-focus
        });
        if (this.action === "Cifrar") {
            new obsidian_1.Setting(contentEl).setName("Confirmar contraseña").addText(text => {
                text.inputEl.type = "password";
                text.setPlaceholder("Repite tu clave...").onChange(value => confirmPass = value);
                text.inputEl.addEventListener('keypress', (e) => { if (e.key === 'Enter')
                    handleAction(); });
            });
        }
        new obsidian_1.Setting(contentEl).addButton(btn => btn.setButtonText(this.action).setCta().onClick(() => handleAction()));
    }
    onClose() { this.contentEl.empty(); }
}
