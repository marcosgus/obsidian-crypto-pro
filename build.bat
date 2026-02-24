@echo off
set /p commitMsg="Introduce el mensaje del commit: "

echo [1/4] Compilando TypeScript...
call npx tsc
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] La compilacion fallo.
    pause
    exit /b %ERRORLEVEL%
)

echo [2/4] Actualizando main.js en la raiz...
copy /Y dist\main.js .\main.js

echo [3/4] Preparando cambios para GitHub...
git add .
git commit -m "%commitMsg%"

echo [4/4] Subiendo al repositorio remoto...
git push origin main

if %ERRORLEVEL% EQU 0 (
    echo [EXITO] Compilado y subido correctamente a GitHub.
) else (
    echo [ERROR] No se pudo subir a GitHub. Verifica tu conexion o permisos.
)

pause