param([string]$Driver, [string]$Arch)
$ErrorActionPreference = 'Stop'

$Drivers = @('zink', 'clvk')
if ($Driver)
{
    if ($Drivers -notcontains $Driver) { throw "unknown driver $Driver; known: $($Drivers -join ', ')" }
    $Drivers = @($Driver)
}

$Targets = @(@{ Arch = 'amd64'; Directory = 'System32' }, @{ Arch = 'x86'; Directory = 'SysWOW64' })
if ($Arch)
{
    $Targets = @($Targets | Where-Object { $_.Arch -eq $Arch })
    if ($Targets.Count -eq 0) { throw "unknown architecture $Arch; known: amd64, x86" }
}

$Here = $PSScriptRoot
$Obj = Join-Path $Here 'obj'
$Bin = Join-Path $Here 'bin'
$Downloads = Join-Path $Obj 'downloads'
New-Item -ItemType Directory -Force $Downloads | Out-Null
foreach ($Target in $Targets) { New-Item -ItemType Directory -Force (Join-Path $Bin $Target.Directory) | Out-Null }

function Get-Pinned([string]$Url, [string]$Sha256)
{
    $File = Join-Path $Downloads ([IO.Path]::GetFileName($Url))
    if ((Test-Path $File) -and (Get-FileHash $File -Algorithm SHA256).Hash -eq $Sha256)
    {
        return $File
    }

    & curl.exe -fsSL --retry 3 -o $File $Url
    if ($LASTEXITCODE -ne 0) { throw "download failed: $Url" }
    if ((Get-FileHash $File -Algorithm SHA256).Hash -ne $Sha256) { throw "SHA-256 mismatch: $Url" }
    return $File
}

function Get-PinnedGit([string]$Url, [string]$Commit, [string]$Directory)
{
    if ((Test-Path (Join-Path $Directory '.git')) -and (& git.exe -C $Directory rev-parse HEAD) -eq $Commit) { return $false }
    if (Test-Path $Directory) { Remove-Item $Directory -Recurse -Force }
    New-Item -ItemType Directory -Force $Directory | Out-Null
    & git.exe -C $Directory init --quiet
    & git.exe -C $Directory fetch --quiet --depth 1 $Url $Commit
    if ($LASTEXITCODE -ne 0) { throw "fetch failed: $Url $Commit" }
    & git.exe -C $Directory -c core.autocrlf=false -c advice.detachedHead=false checkout --quiet FETCH_HEAD
    if ($LASTEXITCODE -ne 0) { throw "checkout failed: $Url $Commit" }
    return $true
}

function Get-Stamp([string[]]$Inputs)
{
    $Sha256 = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($Sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($Inputs -join "`n"))) }
    finally { $Sha256.Dispose() }
}

function Find-VsDevCmd
{
    $Vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $Vswhere)) { throw 'vswhere.exe not found; install Visual Studio with the C++ tools' }
    $Install = & $Vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $Install) { throw 'no Visual Studio with the x64 and x86 C++ tools' }
    return Join-Path $Install 'Common7\Tools\VsDevCmd.bat'
}

# x86 builds need the 64-bit linker for large LLVM links.
function Invoke-DevShell([string]$Arch, [string]$CommandLine, [string]$HostArch = $Arch)
{
    & cmd.exe /c "call `"$VsDevCmd`" -arch=$Arch -host_arch=$HostArch -no_logo >nul && $CommandLine"
    if ($LASTEXITCODE -ne 0) { throw "failed in the $Arch developer shell: $CommandLine" }
}

$VsDevCmd = Find-VsDevCmd

$Venv = Join-Path $Obj 'venv'
$Python = Join-Path $Venv 'Scripts\python.exe'
if (-not (Test-Path $Python))
{
    & python -m venv $Venv
    if ($LASTEXITCODE -ne 0) { throw 'python -m venv failed' }
}
& $Python -m pip install --disable-pip-version-check --quiet --require-hashes --only-binary :all: -r (Join-Path $Here 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'pip install failed' }

$FlexBison = Join-Path $Obj 'winflexbison'
if (-not (Test-Path (Join-Path $FlexBison 'win_flex.exe')))
{
    $Archive = Get-Pinned 'https://github.com/lexxmark/winflexbison/releases/download/v2.5.25/win_flex_bison-2.5.25.zip' `
        '8D324B62BE33604B2C45AD1DD34AB93D722534448F55A16CA7292DE32B6AC135'
    Expand-Archive $Archive $FlexBison -Force
}

$env:PATH = (Join-Path $Venv 'Scripts') + ';' + $FlexBison + ';' + $env:PATH
$env:CC = 'cl'
$env:CXX = 'cl'

foreach ($Name in $Drivers)
{
    . (Join-Path $Here "$Name\build.ps1")
}

$Repo = Resolve-Path (Join-Path $Here '..\..')
$BrovanBin = Join-Path $Repo 'Brovan\bin'
if (Test-Path $BrovanBin)
{
    Get-ChildItem $BrovanBin -Recurse -Filter Brovan.exe | ForEach-Object {
        $Windows = Join-Path $_.DirectoryName 'VirtualFS\C\Windows'
        New-Item -ItemType Directory -Force $Windows | Out-Null
        Copy-Item (Join-Path $Bin '*') $Windows -Recurse -Force
        Write-Host "deployed -> $Windows"
    }
}
