import { App, Editor, MarkdownView, Modal, Plugin, Setting, Notice } from 'obsidian';

export default class CryptoPlugin extends Plugin {
    
    async onload() {
        // 1. Crear el icono en la barra lateral (Ribbon) con detección inteligente
        const ribbonIconEl = this.addRibbonIcon('lock', 'Crypto Pro: Auto-Acción', async () => {
            const view = this.app.workspace.getActiveViewOfType(MarkdownView);
            
            if (!view) {
                new Notice('❌ Abre una nota primero');
                return;
            }

            const editor = view.editor;
            const selection = editor.getSelection();

            if (!selection) {
                new Notice('⚠️ Selecciona el texto para cifrar o descifrar');
                return;
            }

            // Lógica de detección: ¿Es un bloque cifrado?
            const isEncrypted = selection.startsWith('%%ENC:') && selection.endsWith('%%');

            if (isEncrypted) {
                // ACCIÓN: DESCIFRAR
                const data = selection.substring(6, selection.length - 2);
                
                new PasswordModal(this.app, "Descifrar", async (pass) => {
                    try {
                        const decrypted = await this.decrypt(data, pass);
                        editor.replaceSelection(decrypted);
                        new Notice('🔓 Texto descifrado correctamente');
                    } catch (e) {
                        new Notice('❌ Contraseña incorrecta');
                    }
                }).open();

            } else {
                // ACCIÓN: CIFRAR
                new PasswordModal(this.app, "Cifrar", async (pass) => {
                    const encrypted = await this.encrypt(selection, pass);
                    editor.replaceSelection(`%%ENC:${encrypted}%%`);
                    new Notice('🔒 Texto cifrado correctamente');
                }).open();
            }
        });

        // Aplicar clase CSS al icono
        ribbonIconEl.addClass('my-crypto-ribbon-class');

        // 2. Comandos para la paleta (Ctrl+P)
        this.addCommand({
            id: 'crypto-auto-action',
            name: 'Ejecutar Cifrado/Descifrado inteligente',
            callback: () => {
                const view = this.app.workspace.getActiveViewOfType(MarkdownView);
                if (view) {
                    // Reutilizamos la lógica del Ribbon
                    (ribbonIconEl as any).click();
                }
            }
        });
    }

    // --- Lógica Criptográfica ---

    async encrypt(text: string, password: string): Promise<string> {
        const encoder = new TextEncoder();
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        const key = await this.deriveKey(password, salt);
        const encrypted = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv }, key, encoder.encode(text)
        );

        const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
        result.set(salt, 0);
        result.set(iv, salt.length);
        result.set(new Uint8Array(encrypted), salt.length + iv.length);
        
        return btoa(String.fromCharCode(...result));
    }

    async decrypt(base64Data: string, password: string): Promise<string> {
        const data = Uint8Array.from(atob(base64Data), c => c.charCodeAt(0));
        const salt = data.slice(0, 16);
        const iv = data.slice(16, 28);
        const encrypted = data.slice(28);

        const key = await this.deriveKey(password, salt);
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv }, key, encrypted
        );

        return new TextDecoder().decode(decrypted);
    }

    async deriveKey(password: string, salt: Uint8Array) {
        const encoder = new TextEncoder();
        const baseKey = await window.crypto.subtle.importKey(
            "raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]
        );
        return window.crypto.subtle.deriveKey(
            { 
                name: "PBKDF2", 
                salt: salt as unknown as ArrayBuffer,
                iterations: 100000, 
                hash: "SHA-256" 
            },
            baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
        );
    }
}

// --- Clase del Modal ---

class PasswordModal extends Modal {
    constructor(
        app: App, 
        private action: "Cifrar" | "Descifrar", 
        private onSubmit: (pass: string) => void
    ) {
        super(app);
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.createEl("h2", { text: `${this.action} contenido` });

        let pass = "";
        let confirmPass = "";

        new Setting(contentEl)
            .setName("Contraseña")
            .addText(text => {
                text.inputEl.type = "password";
                text.setPlaceholder("Introduce tu clave...")
                    .onChange(value => pass = value);
            });

        if (this.action === "Cifrar") {
            new Setting(contentEl)
                .setName("Confirmar contraseña")
                .addText(text => {
                    text.inputEl.type = "password";
                    text.setPlaceholder("Repite tu clave...")
                        .onChange(value => confirmPass = value);
                });
        }

        new Setting(contentEl)
            .addButton(btn => btn
                .setButtonText(this.action)
                .setCta()
                .onClick(() => {
                    if (this.action === "Cifrar" && pass !== confirmPass) {
                        new Notice("❌ Las contraseñas no coinciden.");
                        return;
                    }
                    if (pass.length === 0) {
                        new Notice("⚠️ La contraseña no puede estar vacía.");
                        return;
                    }
                    this.close();
                    this.onSubmit(pass);
                }));
    }

    onClose() {
        let { contentEl } = this;
        contentEl.empty();
    }
}