@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "HERE=%~dp0"
set "REPO=%GITHUB_WORKSPACE%"

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

if not exist "%HERE%bin" mkdir "%HERE%bin"
if not exist "%HERE%obj\build" mkdir "%HERE%obj\build"

where cl >nul 2>&1
if errorlevel 1 call :init_msvc
where cl >nul 2>&1
if errorlevel 1 (
    echo error: cl.exe not found. Run this from a Visual Studio developer environment on GitHub Actions Windows runners. 1>&2
    exit /b 1
)

pushd "%HERE%"
cl /nologo /O2 /MT /LD vulkan_shim.c /I. /I..\vulkan-headers /Foobj\build\ /Febin\vulkan-1.dll /link /DEF:obj\generated\exports.def /IMPLIB:bin\vulkan-1.lib kernel32.lib
if errorlevel 1 (
    popd
    exit /b 1
)
popd

echo Deploying vulkan-1.dll:
call :deploy "%REPO%\VirtualFS"

if exist "%REPO%\Brovan\bin" (
    for /r "%REPO%\Brovan\bin" %%E in (Brovan.exe) do call :deploy "%%~dpE\VirtualFS"
)

if exist "%REPO%\Brovan.Graphics" (
    for /r "%REPO%\Brovan.Graphics" %%E in (Brovan.exe) do call :deploy "%%~dpE\VirtualFS"
)

exit /b 0

:init_msvc
set "VSDEVCMD="
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
        goto :have_vsdevcmd
    )
)

for /f "usebackq delims=" %%P in (`where vswhere.exe 2^>nul`) do (
    for /f "usebackq delims=" %%Q in (`"%%P" -latest -products * -requires Microsoft.Component.MSBuild -find Common7\Tools\VsDevCmd.bat 2^>nul`) do (
        if exist "%%Q" (
            set "VSDEVCMD=%%Q"
            goto :have_vsdevcmd
        )
    )
)

exit /b 1

:have_vsdevcmd
call "%VSDEVCMD%" -arch=amd64 -host_arch=amd64 >nul
exit /b 0

:deploy
set "VFS=%~1\C\Windows\System32"
if not exist "%VFS%" mkdir "%VFS%"
copy /Y "%HERE%bin\vulkan-1.dll" "%VFS%\vulkan-1.dll" >nul
echo   deployed -^> %VFS%\vulkan-1.dll
exit /b 0