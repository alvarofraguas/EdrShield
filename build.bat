@echo off
REM ═══════════════════════════════════════════════════
REM  EdrShield build script (Community Edition)
REM  Compiles edrshield.exe
REM
REM  Requirements:
REM    - Visual Studio Build Tools (MSVC)
REM
REM  Usage:
REM    build.bat              Build exe
REM    build.bat clean        Remove build artifacts
REM ═══════════════════════════════════════════════════

setlocal enabledelayedexpansion

set VERSION=1.0.0
set OUTDIR=build
set EXE=%OUTDIR%\edrshield.exe

REM ─── Detect build tools ───
where cl >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] MSVC not found. Trying to load vcvars64...
    if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
        call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    ) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
        call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    ) else if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
        call "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    ) else (
        echo [!] Cannot find Visual Studio. Install Build Tools 2022.
        exit /b 1
    )
)

if not exist %OUTDIR% mkdir %OUTDIR%

REM ─── Parse command ───
set CMD=%1
if "%CMD%"=="" set CMD=all
if "%CMD%"=="clean" goto :clean

REM ═══════════════════════════════════════════════════
REM  BUILD EXE
REM ═══════════════════════════════════════════════════

echo.
echo  Compiling edrshield.exe...
echo.

REM Compile resource file (icon + version info)
if exist src\resources.rc (
    rc /nologo /fo %OUTDIR%\resources.res src\resources.rc
    if %ERRORLEVEL% neq 0 (
        echo [!] Resource compilation failed, building without icon...
        set RES_FILE=
    ) else (
        set RES_FILE=%OUTDIR%\resources.res
    )
) else (
    set RES_FILE=
)

cl /O2 /W4 /WX- /Fe:%EXE% ^
    src\main.c src\log.c src\wfp.c src\qos.c ^
    src\discovery.c src\service.c ^
    %RES_FILE% ^
    /link fwpuclnt.lib ole32.lib advapi32.lib shell32.lib ^
    /SUBSYSTEM:CONSOLE /MACHINE:X64

if %ERRORLEVEL% neq 0 (
    echo [!] Compilation failed.
    exit /b 1
)

echo.
echo  [OK] %EXE% built successfully
echo.

REM Clean up .obj files
del /q *.obj >nul 2>&1

goto :done

REM ═══════════════════════════════════════════════════
REM  CLEAN
REM ═══════════════════════════════════════════════════
:clean

echo  Cleaning build artifacts...
if exist %OUTDIR% rmdir /s /q %OUTDIR%
del /q *.obj >nul 2>&1
echo  [OK] Clean.
goto :eof

:done
echo.
echo  ═══════════════════════════════════════════
echo  Build complete.
echo  ═══════════════════════════════════════════
echo.
if exist %EXE% (
    echo  EXE:  %EXE%
    echo.
    echo  Install:
    echo    edrshield.exe install
    echo    sc start EdrShieldSvc
    echo.
    echo  Uninstall:
    echo    edrshield.exe uninstall
)
echo.
