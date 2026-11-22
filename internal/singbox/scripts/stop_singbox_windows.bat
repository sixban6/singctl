@echo off
setlocal enabledelayedexpansion

REM ================================================
REM Description: Windows sing-box TUN mode stop script
REM Purpose: Stop sing-box TUN mode proxy service on Windows
REM ================================================

echo [INFO] Stopping sing-box service...

REM Check if sing-box is running
tasklist /FI "IMAGENAME eq sing-box.exe" 2>NUL | find /I /N "sing-box.exe" > NUL
if %ERRORLEVEL%==0 (
    echo [INFO] Found running sing-box process, stopping...
    
    REM Try graceful shutdown first
    taskkill /IM sing-box.exe >NUL 2>&1
    timeout /t 2 /nobreak >NUL
    
    REM Check if still running, force kill if necessary
    tasklist /FI "IMAGENAME eq sing-box.exe" 2>NUL | find /I /N "sing-box.exe" > NUL
    if %ERRORLEVEL%==0 (
        echo [INFO] Force stopping sing-box process...
        taskkill /F /IM sing-box.exe >NUL 2>&1
        timeout /t 1 /nobreak >NUL
    )
    
    REM Final check
    tasklist /FI "IMAGENAME eq sing-box.exe" 2>NUL | find /I /N "sing-box.exe" > NUL
    if %ERRORLEVEL%==0 (
        echo [ERROR] Unable to stop sing-box process, please check manually
        exit /b 1
    ) else (
        echo [SUCCESS] sing-box service stopped successfully
    )
) else (
    echo [INFO] No running sing-box service found
)

REM Windows TUN mode doesn't require additional network configuration cleanup
echo [INFO] Windows TUN mode stop completed

exit /b 0