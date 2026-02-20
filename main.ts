import { App, Editor, MarkdownView, Modal, Plugin, Setting, Notice } from 'obsidian';

export default class CryptoPlugin extends Plugin {
    async onload() {
        // Comando para Cifrar
        this.addCommand({
            id: 'encrypt-selection',
            name: 'Cifrar texto seleccionado',
            editorCallback: async (editor: Editor) => {
                const selection = editor.getSelection();
                if (!selection) return;
                
                new PasswordModal(this.app, "Cifrar", async (pass) => {
                    const encrypted = await this.encrypt(selection, pass);
                    editor.replaceSelection(`%%ENC:${encrypted}%%`);
                }).open();
            }
        });

        // Comando para Descifrar
        this.addCommand({
            id: 'decrypt-selection',
            name: 'Descifrar texto seleccionado',
            editorCallback: async (editor: Editor) => {
                const selection = editor.getSelection();
                // Extraer el contenido del bloque %%ENC:...%%
                const match = selection.match(/%%ENC:(.*)%%/);
                const data = match ? match[1] : selection;

                new PasswordModal(this.app, "Descifrar", async (pass) => {
                    try {
                        const decrypted = await this.decrypt(data, pass);
                        editor.replaceSelection(decrypted);
                    } catch (e) {
                        console.error("Error al descifrar: Contraseña incorrecta o datos corruptos.");
                    }
                }).open();
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

        // Concatenamos Salt + IV + Texto Cifrado para que sea auto-contenido
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

// Cambia esta línea en la función deriveKey
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

// Modal simple para pedir la contraseña
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

        // Campo de Contraseña
        new Setting(contentEl)
            .setName("Contraseña")
            .addText(text => {
                text.inputEl.type = "password"; // OCULTA los caracteres
                text.setPlaceholder("Introduce tu clave...")
                    .onChange(value => pass = value);
            });

        // Solo añadir "Confirmar" si estamos cifrando
        if (this.action === "Cifrar") {
            new Setting(contentEl)
                .setName("Confirmar contraseña")
                .addText(text => {
                    text.inputEl.type = "password"; // OCULTA los caracteres
                    text.setPlaceholder("Repite tu clave...")
                        .onChange(value => confirmPass = value);
                });
        }

        // Botón de Acción
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