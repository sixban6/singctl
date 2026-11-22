@echo off
setlocal enabledelayedexpansion

REM ================================================
REM Description: Windows sing-box TUN mode start script
REM Purpose: Start sing-box TUN mode proxy service on Windows
REM ================================================

set "CONFIG_FILE=%LOCALAPPDATA%\sing-box\config.json"
set "SING_BOX_EXE=%LOCALAPPDATA%\Programs\sing-box\sing-box.exe"

echo [INFO] Starting sing-box service (TUN mode)...

REM Check if sing-box executable exists
if not exist "%SING_BOX_EXE%" (
    echo [ERROR] sing-box executable not found: %SING_BOX_EXE%
    echo [ERROR] Please install sing-box first: singctl install sb
    exit /b 1
)

REM Stop existing sing-box processes
echo [INFO] Checking for running sing-box processes...
tasklist /FI "IMAGENAME eq sing-box.exe" 2>NUL | find /I /N "sing-box.exe" > NUL
if %ERRORLEVEL%==0 (
    echo [INFO] Found running sing-box process, stopping...
    taskkill /F /IM sing-box.exe >NUL 2>&1
    timeout /t 2 /nobreak >NUL
    echo [INFO] Stopped existing sing-box service
) else (
    echo [INFO] No running sing-box service found
)

REM Check network connectivity
echo [INFO] Checking network connection...
ping -n 1 8.8.8.8 >NUL 2>&1
if %ERRORLEVEL% neq 0 (
    echo [WARN] Network connectivity check failed, but will continue startup
)

REM Create config directory if not exists
if not exist "%LOCALAPPDATA%\sing-box" (
    mkdir "%LOCALAPPDATA%\sing-box"
    echo [INFO] Created config directory: %LOCALAPPDATA%\sing-box
)

REM Verify configuration file
if not exist "%CONFIG_FILE%" (
    echo [ERROR] Configuration file not found: %CONFIG_FILE%
    exit /b 1
)

REM Validate configuration
echo [INFO] Validating configuration file...
"%SING_BOX_EXE%" check -c "%CONFIG_FILE%" >NUL 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Configuration file validation failed
    exit /b 1
)
echo [INFO] Configuration file validation passed

REM Start sing-box service
echo [INFO] Starting sing-box service (TUN mode)...
start /B "" "%SING_BOX_EXE%" run -c "%CONFIG_FILE%" >NUL 2>&1

REM Wait and check if service started successfully
timeout /t 3 /nobreak >NUL
tasklist /FI "IMAGENAME eq sing-box.exe" 2>NUL | find /I /N "sing-box.exe" > NUL
if %ERRORLEVEL%==0 (
    echo [SUCCESS] sing-box started successfully ^(TUN mode^)
    echo [INFO] Service is running in background
) else (
    echo [ERROR] sing-box startup failed, please check logs
    exit /b 1
)

exit /b 0