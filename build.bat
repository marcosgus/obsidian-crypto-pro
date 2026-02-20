@echo off
echo [1/3] Compilando TypeScript...
call npx tsc

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] La compilacion fallo. Revisa el codigo.
    pause
    exit /b %ERRORLEVEL%
)

echo [2/3] Moviendo main.js a la raiz del plugin...
copy /Y dist\main.js .\main.js

echo [3/3] Despliegue finalizado con exito.
echo RECUERDA: En Obsidian, desactiva y vuelve a activar el plugin "Crypto Pro".
pause