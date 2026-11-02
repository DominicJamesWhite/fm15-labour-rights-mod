@echo off
rem Opens the rule-set chooser (tools\launcher.pyw: vanilla, labour rights or nostalgia), which starts
rem FM15 through Steam and applies the patches in memory. With arguments, runs tools\fm15_loader.py
rem directly instead, e.g. "Launch FM15 (modded).bat" --mode nostalgia
cd /d "%~dp0"
if "%~1"=="" (
    start "" "C:\Python313\pythonw.exe" tools\launcher.pyw
    exit /b
)
title FM15 mod loader
"C:\Python313\python.exe" tools\fm15_loader.py %*
if errorlevel 1 (
    echo.
    echo Something went wrong - see above. Press any key to close.
    pause >nul
) else (
    timeout /t 5
)
