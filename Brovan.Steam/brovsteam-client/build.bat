@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "HERE=%~dp0"
set "REPO=%GITHUB_WORKSPACE%"

if defined REPO if not exist "%REPO%" set "REPO="

if not defined REPO (
    for /f "delims=" %%i in ('git -C "%HERE%" rev-parse --show-toplevel 2^>nul') do set "REPO=%%i"
)

if not defined REPO (
    for %%i in ("%HERE%..\..") do set "REPO=%%~fi"
)

if not exist "%HERE%obj\generated\brovsteam_gen.c" (
    echo error: generated sources missing. Build the Brovan project first ^(it runs the code generator^). 1>&2
    exit /b 1
)

if not exist "%HERE%obj\generated\exports.def" (
    echo error: generated exports.def missing. 1>&2
    exit /b 1
)

if not exist "%HERE%bin" md "%HERE%bin" || exit /b 1
if not exist "%HERE%obj\build" md "%HERE%obj\build" || exit /b 1

set "COMPILER="
set "MODE="

rem Resolved through vswhere, an unrelated cl on PATH would otherwise win.
call :init_msvc
if defined COMPILER goto :have_compiler

for %%T in (gcc.exe clang.exe) do (
    if not defined COMPILER (
        for /f "delims=" %%C in ('where %%T 2^>nul') do (
            set "COMPILER=%%~fC"
            set "MODE=gnu"
            goto :have_compiler
        )
    )
)

echo error: no supported compiler found. Install MSVC, gcc, or clang. 1>&2
exit /b 1

:have_compiler
pushd "%HERE%" || exit /b 1

if /i "%MODE%"=="msvc" (
    "%COMPILER%" /nologo /O2 /MT /LD steamclient_shim.c /I. /Fo"obj\build\steamclient_shim.obj" /Fe"bin\steamclient64.dll" /link /DEF:"obj\generated\exports.def" /IMPLIB:"bin\steamclient64.lib" kernel32.lib
) else (
    "%COMPILER%" -O2 -c "steamclient_shim.c" -I. -o "obj\build\steamclient_shim.o"
    if not errorlevel 1 (
        "%COMPILER%" -shared -static -static-libgcc -o "bin\steamclient64.dll" "obj\build\steamclient_shim.o" "obj\generated\exports.def" -Wl,--out-implib,"bin\steamclient64.lib" -lkernel32
    )
)

if errorlevel 1 (
    popd
    exit /b 1
)

popd

echo Deploying steamclient64.dll:

for /f "delims=" %%E in ('dir /s /b /a-d "%REPO%\Brovan\bin\Brovan.exe" 2^>nul') do call :deploy "%%~dpEVirtualFS"

exit /b 0

:init_msvc
set "VSWHERE="
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not defined VSWHERE if exist "%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not defined VSWHERE exit /b 1

set "VSDEVCMD="
for /f "usebackq delims=" %%Q in (`"%VSWHERE%" -latest -products * -find Common7\Tools\VsDevCmd.bat 2^>nul`) do set "VSDEVCMD=%%Q"
if not defined VSDEVCMD exit /b 1
if not exist "%VSDEVCMD%" exit /b 1

call "%VSDEVCMD%" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 1

for /f "usebackq delims=" %%C in (`"%VSWHERE%" -latest -products * -find VC\Tools\MSVC\**\bin\Hostx64\x64\cl.exe 2^>nul`) do set "COMPILER=%%C"
if not defined COMPILER exit /b 1

set "MODE=msvc"
exit /b 0

:deploy
set "VFS=%~1\C\Program Files (x86)\Steam"
if not exist "%VFS%" md "%VFS%" || exit /b 1
copy /Y "%HERE%bin\steamclient64.dll" "%VFS%\steamclient64.dll" >nul
if errorlevel 1 exit /b 1
echo   deployed -^> %VFS%\steamclient64.dll
exit /b 0
