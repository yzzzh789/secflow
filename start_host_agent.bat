@echo off
setlocal

set "ROOT_DIR=%~dp0"
set "POWERSHELL_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "TARGET_SCRIPT=%ROOT_DIR%scripts\start_host_agent.ps1"

if not exist "%TARGET_SCRIPT%" (
    echo Cannot find "%TARGET_SCRIPT%"
    pause
    exit /b 1
)

"%POWERSHELL_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%TARGET_SCRIPT%" %*
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
    echo.
    echo start_host_agent failed with exit code %EXIT_CODE%.
    pause
)

exit /b %EXIT_CODE%
