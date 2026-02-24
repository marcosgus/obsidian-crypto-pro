@echo off
rem set /p commitMsg="Introduce el mensaje del commit: "

echo [1/4] Compilando TypeScript...
call npx tsc
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] La compilacion fallo.
    pause
    exit /b %ERRORLEVEL%
)

echo [2/4] Actualizando main.js en la raiz...
copy /Y dist\main.js .\main.js

rem echo [3/4] Preparando cambios para GitHub...
rem git add .
rem git commit -m "%commitMsg%"

rem echo [4/4] Subiendo al repositorio remoto...
rem git push origin main

rem if %ERRORLEVEL% EQU 0 (
rem    echo [EXITO] Compilado y subido correctamente a GitHub.
rem ) else (
rem     echo [ERROR] No se pudo subir a GitHub. Verifica tu conexion o permisos.
rem )

pause