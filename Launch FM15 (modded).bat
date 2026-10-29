@echo off
rem Starts FM15 through Steam and applies the labour-rights patches in memory (tools\fm15_loader.py).
title FM15 mod loader
cd /d "%~dp0"
"C:\Python313\python.exe" tools\fm15_loader.py %*
if errorlevel 1 (
    echo.
    echo Something went wrong - see above. Press any key to close.
    pause >nul
) else (
    timeout /t 5
)
