@echo off
setlocal
cd /d "%~dp0"

py -c "import pefile" >nul 2>&1

if errorlevel 1 (
    echo pefile is not installed. Installing it now...
    py -m pip install pefile
  
    if errorlevel 1 (
        echo.
        echo ERROR: Could not install pefile.
        echo Try: py -m pip install pefile
        pause
        exit /b 1
    )
)

echo.
echo SG English translation patcher
echo.

py main.py --report patch-report.json --dump-missing missing-report.json %*

set ERR=%ERRORLEVEL%
echo.
if not "%ERR%"=="0" (
    echo Translation failed with exit code %ERR%.
) else (
    echo Translation finished. Patched files are in the output folder, one subfolder per file version.
)

pause
exit /b %ERR%
