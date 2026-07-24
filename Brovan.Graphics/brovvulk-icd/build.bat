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

if not exist "%HERE%obj\generated\brovvulk_gen.c" (
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

where cl >nul 2>&1
if not errorlevel 1 (
    for /f "delims=" %%C in ('where cl 2^>nul') do (
        set "COMPILER=%%~fC"
        set "MODE=msvc"
        goto :have_compiler
    )
)

where clang-cl >nul 2>&1
if not errorlevel 1 (
    if not defined VSCMD_VER call :init_msvc
    if not errorlevel 1 (
        for /f "delims=" %%C in ('where clang-cl 2^>nul') do (
            set "COMPILER=%%~fC"
            set "MODE=msvc"
            goto :have_compiler
        )
    )
)

for %%T in (gcc clang cc) do (
    if not defined COMPILER (
        for /f "delims=" %%C in ('where %%T 2^>nul') do (
            set "COMPILER=%%~fC"
            set "MODE=gnu"
            goto :have_compiler
        )
    )
)

call :init_msvc
if not errorlevel 1 (
    where cl >nul 2>&1
    if not errorlevel 1 (
        for /f "delims=" %%C in ('where cl 2^>nul') do (
            set "COMPILER=%%~fC"
            set "MODE=msvc"
            goto :have_compiler
        )
    )

    where clang-cl >nul 2>&1
    if not errorlevel 1 (
        for /f "delims=" %%C in ('where clang-cl 2^>nul') do (
            set "COMPILER=%%~fC"
            set "MODE=msvc"
            goto :have_compiler
        )
    )
)

echo error: no supported compiler found. Install MSVC, clang-cl, gcc, or clang. 1>&2
exit /b 1

:have_compiler
pushd "%HERE%" || exit /b 1

if /i "%MODE%"=="msvc" (
    "%COMPILER%" /nologo /O2 /MT /LD vulkan_shim.c /I. /I"..\vulkan-headers" /Fo"obj\build\" /Fe"bin\vulkan-1.dll" /link /DEF:"obj\generated\exports.def" /IMPLIB:"bin\vulkan-1.lib" kernel32.lib
) else (
    "%COMPILER%" -O2 -c "vulkan_shim.c" -I. -I"..\vulkan-headers" -o "obj\build\vulkan_shim.o"
    if not errorlevel 1 (
        "%COMPILER%" -shared -static -static-libgcc -static-libstdc++ -o "bin\vulkan-1.dll" "obj\build\vulkan_shim.o" "obj\generated\exports.def" -Wl,--out-implib,"bin\vulkan-1.lib" -lkernel32
    )
)

if errorlevel 1 (
    popd
    exit /b 1
)

popd

call :build_x86

echo Deploying vulkan-1.dll:

for /f "delims=" %%E in ('dir /s /b /a-d "%REPO%\Brovan\bin\Brovan.exe" 2^>nul') do call :deploy "%%~dpEVirtualFS"

exit /b 0

:build_x86

set "HAVE_X86="
call :find_vsdevcmd
if errorlevel 1 (
    echo   warning: VsDevCmd not found; skipping 32-bit SysWOW64 shim. 1>&2
    exit /b 0
)
if not exist "%HERE%bin\x86" md "%HERE%bin\x86" || exit /b 1
if not exist "%HERE%obj\build" md "%HERE%obj\build" || exit /b 1

setlocal
set "VSCMD_VER="
call "%VSDEVCMD%" -arch=x86 -host_arch=amd64 >nul
if errorlevel 1 goto :x86_failed

cl /nologo /O2 /MT /LD "%HERE%vulkan_shim.c" /I"%HERE%." /I"%HERE%..\vulkan-headers" /Fo"%HERE%obj\build\vulkan_shim_x86.obj" /Fe"%HERE%bin\x86\vulkan-1.dll" /link /DEF:"%HERE%obj\generated\exports.def" /IMPLIB:"%HERE%bin\x86\vulkan-1.lib" kernel32.lib
if errorlevel 1 goto :x86_failed

endlocal & set "HAVE_X86=1"
exit /b 0

:x86_failed
endlocal
echo   warning: 32-bit shim build failed; SysWOW64 shim not updated. 1>&2
exit /b 0

:init_msvc
call :find_vsdevcmd
if errorlevel 1 exit /b 1
call "%VSDEVCMD%" -arch=amd64 -host_arch=amd64 >nul
exit /b %errorlevel%

:find_vsdevcmd
set "VSDEVCMD="

set "VSWHERE="
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not defined VSWHERE if exist "%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"

if defined VSWHERE (
    set "VSWHERE_OUT=%TEMP%\brovvulk_vsdevcmd.txt"
    "%VSWHERE%" -latest -products * -find Common7\Tools\VsDevCmd.bat >"!VSWHERE_OUT!" 2>nul
    for /f "usebackq delims=" %%Q in ("!VSWHERE_OUT!") do (
        if exist "%%Q" (
            set "VSDEVCMD=%%Q"
            del /q "!VSWHERE_OUT!" >nul 2>&1
            goto :found_vsdevcmd
        )
    )
    del /q "!VSWHERE_OUT!" >nul 2>&1
)

for %%P in (
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\Common7\Tools\VsDevCmd.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Professional\Common7\Tools\VsDevCmd.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\BuildTools\Common7\Tools\VsDevCmd.bat"
) do (
    if exist %%~P (
        set "VSDEVCMD=%%~P"
        goto :found_vsdevcmd
    )
)

exit /b 1

:found_vsdevcmd
exit /b 0

:deploy
set "VFS=%~1\C\Windows\System32"
if not exist "%VFS%" md "%VFS%" || exit /b 1
copy /Y "%HERE%bin\vulkan-1.dll" "%VFS%\vulkan-1.dll" >nul
if errorlevel 1 exit /b 1
echo   deployed -^> %VFS%\vulkan-1.dll
if defined HAVE_X86 (
    if not exist "%~1\C\Windows\SysWOW64" md "%~1\C\Windows\SysWOW64" || exit /b 1
    copy /Y "%HERE%bin\x86\vulkan-1.dll" "%~1\C\Windows\SysWOW64\vulkan-1.dll" >nul
    if errorlevel 1 exit /b 1
    echo   deployed -^> %~1\C\Windows\SysWOW64\vulkan-1.dll
)
exit /b 0
