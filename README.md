# Crypto Pro: Secure AES-GCM Encryption for Obsidian 🔒

Moderno plugin de cifrado diseñado para proteger información sensible dentro de tus notas utilizando estándares de criptografía de grado industrial.

## ✨ Características Principales
- **Cifrado AES-GCM (256-bit)**: Proporciona confidencialidad e integridad (Cifrado Autenticado).
- **Entrada de Contraseña Segura**: Campos de texto enmascarados para evitar que la clave sea visible al tipear.
- **Validación de Doble Factor**: Confirmación de contraseña al cifrar para prevenir errores de escritura y pérdida de datos.
- **Integración Nativa**: Funciona mediante comandos de Obsidian y permite asignar Hotkeys personalizados.

## 🚀 Cómo empezar
1. Selecciona el texto que deseas proteger.
2. Ejecuta el comando `Crypto Pro: Cifrar texto seleccionado`.
3. Para recuperar el contenido, selecciona el bloque cifrado y ejecuta `Crypto Pro: Descifrar texto seleccionado`.

## 🛠️ Instalación Manual
1. Descarga el `main.js`, `manifest.json` y `styles.css` de la sección de Releases.
2. Crea una carpeta llamada `obsidian-crypto-pro` en `.obsidian/plugins/` de tu vault.
3. Copia los archivos dentro de esa carpeta y activa el plugin en los ajustes de Obsidian.