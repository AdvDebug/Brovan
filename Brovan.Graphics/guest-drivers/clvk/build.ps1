$ClvkSources = [ordered]@{
    'clvk' = 'https://github.com/kpet/clvk', '87d6dd3c55db4299b6e364bb8d41ba00d6eda7d7'
    'clvk\external\clspv' = 'https://github.com/google/clspv', '7ee3a40e652b3649d175758f72d7af98b9450a68'
    'clvk\external\clspv\third_party\llvm' = 'https://github.com/llvm/llvm-project', '71a85ef89fc1997205104b72447e0dc2c4ad83da'
    'clvk\external\OpenCL-Headers' = 'https://github.com/KhronosGroup/OpenCL-Headers', '386ca390b2f52efeb3e1a55a500690eb8013f60e'
    'clvk\external\SPIRV-Headers' = 'https://github.com/KhronosGroup/SPIRV-Headers', '2b7475f6d664efbad4d4315c94ecec9640831e5b'
    'clvk\external\SPIRV-Tools' = 'https://github.com/KhronosGroup/SPIRV-Tools', 'ba9a9e32160e2500ce1e48cc563a8fedaf596e6e'
    'clvk\external\SPIRV-LLVM-Translator' = 'https://github.com/KhronosGroup/SPIRV-LLVM-Translator', 'c4a6b42303c6b45a64ede3d1c0399dce2d90f3fc'
    'Vulkan-Headers' = 'https://github.com/KhronosGroup/Vulkan-Headers', 'b5c8f996196ba4aa6d8f97e52b5d3b6e70f7e4e2'
    'Vulkan-Loader' = 'https://github.com/KhronosGroup/Vulkan-Loader', '32fcb949e253cbeb40cda7ea76122b492db579ae'
}

$PythonCMake = $Python -replace '\\', '/'
# LLVM declares its link pool twice here, so use CMake's pool.
$ClvkOptions = @(
    '-G Ninja', '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_POLICY_DEFAULT_CMP0091=NEW', '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded',
    '-DCLVK_CLSPV_ONLINE_COMPILER=ON', '-DCLVK_BUILD_TESTS=OFF', '-DCLVK_VULKAN_IMPLEMENTATION=custom',
    '-DLLVM_INCLUDE_TESTS=OFF', '-DLLVM_INCLUDE_BENCHMARKS=OFF', '-DLLVM_INCLUDE_EXAMPLES=OFF', '-DCLANG_INCLUDE_TESTS=OFF',
    '-DCMAKE_JOB_POOLS=link=2', '-DCMAKE_JOB_POOL_LINK=link', '-DCCACHE_FOUND=OFF', '-DCCACHE_ALLOWED=OFF',
    "-DPython3_EXECUTABLE=$PythonCMake"
) -join ' '

# LLVM paths exceed MAX_PATH without a short build root.
$ClvkData = Join-Path $Obj 'clvk'
$ClvkObj = Join-Path $env:SystemDrive ('bgd-' + (Get-Stamp @($ClvkData.ToLowerInvariant())).Replace('-', '').Substring(0, 8))
New-Item -ItemType Directory -Force $ClvkData | Out-Null
$Link = Get-Item $ClvkObj -Force -ErrorAction SilentlyContinue
if (-not $Link)
{
    New-Item -ItemType Junction -Path $ClvkObj -Target $ClvkData | Out-Null
}
elseif ($Link.LinkType -ne 'Junction' -or [string]$Link.Target -ne $ClvkData)
{
    throw "$ClvkObj is in the way; it has to be a junction to $ClvkData"
}

$Fetched = $false
foreach ($Entry in $ClvkSources.GetEnumerator())
{
    if (Get-PinnedGit $Entry.Value[0] $Entry.Value[1] (Join-Path $ClvkObj $Entry.Key)) { $Fetched = $true }
}

$Pins = @($ClvkSources.Values | ForEach-Object { $_[1] })
$Patches = @(Get-ChildItem (Join-Path $PSScriptRoot 'patches') -Filter *.patch -ErrorAction SilentlyContinue | Sort-Object Name)
$SourceStamp = Get-Stamp ($Pins + ($Patches | ForEach-Object { (Get-FileHash $_.FullName -Algorithm SHA256).Hash }))
$SourceStampFile = Join-Path $ClvkObj 'sources.txt'
$PatchedFile = Join-Path $ClvkObj 'patched.txt'
if ($Fetched -or -not (Test-Path $SourceStampFile) -or (Get-Content $SourceStampFile -Raw).Trim() -ne $SourceStamp)
{
    Remove-Item $SourceStampFile -ErrorAction SilentlyContinue

    # git show bypasses line ending conversion and the index stat cache.
    $Touched = @($Patches | ForEach-Object { Select-String -Path $_.FullName -Pattern '^(?:---|\+\+\+) [ab]/(.+)$' } | ForEach-Object { $_.Matches[0].Groups[1].Value } | Sort-Object -Unique)
    $Restore = $Touched + @(if (Test-Path $PatchedFile) { Get-Content $PatchedFile })
    foreach ($File in ($Restore | Sort-Object -Unique))
    {
        $Path = $File -replace '/', '\'
        $Key = @($ClvkSources.Keys | Where-Object { $Path.StartsWith($_ + '\', [StringComparison]::OrdinalIgnoreCase) } | Sort-Object Length -Descending)[0]
        if (-not $Key) { throw "patched file outside the sources: $File" }
        $Repository = Join-Path $ClvkObj $Key
        $Relative = $Path.Substring($Key.Length + 1) -replace '\\', '/'
        $Target = Join-Path $ClvkObj $Path
        & cmd.exe /c "git -C `"$Repository`" cat-file -e HEAD:$Relative 2>nul"
        if ($LASTEXITCODE -ne 0)
        {
            if (Test-Path $Target) { Remove-Item $Target -Force }
            continue
        }
        & cmd.exe /c "git -C `"$Repository`" show HEAD:$Relative > `"$Target`""
        if ($LASTEXITCODE -ne 0) { throw "could not restore $File" }
    }

    # Git resolves the junction before it checks the ceiling.
    $env:GIT_CEILING_DIRECTORIES = $Obj
    foreach ($Patch in $Patches)
    {
        & git.exe -C $ClvkObj -c core.autocrlf=false apply --whitespace=nowarn $Patch.FullName
        if ($LASTEXITCODE -ne 0) { throw "patch does not apply: $($Patch.Name)" }
    }
    Set-Content $PatchedFile $Touched
    Set-Content $SourceStampFile $SourceStamp
}

$Stamp = Get-Stamp (@($ClvkObj, $ClvkOptions) + $Pins)
$StampFile = Join-Path $ClvkObj 'stamp.txt'
if (-not (Test-Path $StampFile) -or (Get-Content $StampFile -Raw).Trim() -ne $Stamp)
{
    Get-ChildItem $ClvkObj -Directory -Filter 'build-*' | Remove-Item -Recurse -Force
    Set-Content $StampFile $Stamp
}

$HeadersInstall = Join-Path $ClvkObj 'build-vulkan-headers'
if (-not (Test-Path (Join-Path $HeadersInstall 'include\vulkan\vulkan.h')))
{
    Invoke-DevShell 'amd64' "cmake -S `"$ClvkObj\Vulkan-Headers`" -B `"$ClvkObj\build-vulkan-headers-tree`" -G Ninja -DCMAKE_INSTALL_PREFIX=`"$HeadersInstall`" && cmake --install `"$ClvkObj\build-vulkan-headers-tree`""
}

# Build the loader only for the import library used with BrovVulk.
foreach ($Target in $Targets)
{
    $LoaderDir = Join-Path $ClvkObj ('build-loader-' + $Target.Arch)
    $ImportLibrary = Join-Path $LoaderDir 'loader\vulkan-1.lib'
    if (-not (Test-Path $ImportLibrary))
    {
        Invoke-DevShell $Target.Arch "cmake -S `"$ClvkObj\Vulkan-Loader`" -B `"$LoaderDir`" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=`"$HeadersInstall`" -DBUILD_TESTS=OFF -DUPDATE_DEPS=OFF && ninja -C `"$LoaderDir`" vulkan" 'amd64'
    }

    $BuildDir = Join-Path $ClvkObj ('build-' + $Target.Arch)
    if (-not (Test-Path (Join-Path $BuildDir 'build.ninja')))
    {
        $Vulkan = "-DVulkan_INCLUDE_DIRS=`"$HeadersInstall\include`" -DVulkan_LIBRARIES=`"$ImportLibrary`""
        Invoke-DevShell $Target.Arch "cmake -S `"$ClvkObj\clvk`" -B `"$BuildDir`" $ClvkOptions $Vulkan" 'amd64'
    }
    Invoke-DevShell $Target.Arch "ninja -C `"$BuildDir`" OpenCL" 'amd64'
    Copy-Item (Join-Path $BuildDir 'src\OpenCL.dll') (Join-Path $Bin "$($Target.Directory)\clvk.dll") -Force
}
