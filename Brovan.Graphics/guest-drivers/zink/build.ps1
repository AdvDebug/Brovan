$MesaVersion = '26.2.5'
$MesaSha256 = '794B3D1729075DAE7EBD47C7283B7CA0CDB5DEC668F7F11CC0A5D82F6138A0A5'

$MesaOptions = @(
    '--buildtype=release', '--wrap-mode=nodownload', '-Db_vscrt=mt', '-Dplatforms=windows',
    '-Dgallium-drivers=zink', '-Dvulkan-drivers=', '-Dllvm=disabled', '-Dopengl=true',
    '-Dgles1=disabled', '-Dgles2=disabled', '-Degl=disabled', '-Dglx=disabled', '-Dgbm=disabled',
    '-Dbuild-tests=false', '-Dmicrosoft-clc=disabled', '-Dgallium-d3d10umd=false', '-Dgallium-va=disabled',
    '-Dgallium-mediafoundation=disabled', '-Dgallium-rusticl=false', '-Dteflon=false', '-Dvideo-codecs=',
    '-Dspirv-tools=disabled', '-Dzstd=disabled', '-Dzlib=disabled', '-Dshader-cache=disabled',
    '-Dexpat=disabled', '-Dxmlconfig=disabled', '-Dvalgrind=disabled', '-Dlibunwind=disabled'
) -join ' '

# Mesa checks versioned Python names before python3.
$PythonPath = $Python -replace '\\', '/'
$PythonNames = @('python', 'python3') + (10..16 | ForEach-Object { "python3.$_" })

# win_flex and win_bison can delete each other's files in a shared TEMP, so each run gets a TEMP of its own.
$OwnTemp = 'import os,subprocess,sys,tempfile;d=tempfile.TemporaryDirectory();r=subprocess.call(sys.argv[1:],env=dict(os.environ,TEMP=d.name,TMP=d.name));d.cleanup();sys.exit(r)'
$NativeLines = @('[binaries]') + ($PythonNames | ForEach-Object { "$_ = '$PythonPath'" }) + (@('win_flex', 'win_bison') | ForEach-Object {
    "$_ = ['$PythonPath', '-c', '$OwnTemp', '$((Join-Path $FlexBison "$_.exe") -replace '\\', '/')']"
})

$ZinkObj = Join-Path $Obj 'zink'
$MesaSource = Join-Path $ZinkObj "mesa-$MesaVersion"
$NativeFile = Join-Path $ZinkObj 'native.ini'
$Patches = @(Get-ChildItem (Join-Path $PSScriptRoot 'patches') -Filter *.patch -ErrorAction SilentlyContinue | Sort-Object Name)

$Inputs = @($MesaVersion, $MesaOptions) + $NativeLines + ($Patches | ForEach-Object { (Get-FileHash $_.FullName -Algorithm SHA256).Hash })
$Stamp = Get-Stamp $Inputs
$StampFile = Join-Path $ZinkObj 'stamp.txt'
if (-not (Test-Path $StampFile) -or (Get-Content $StampFile -Raw).Trim() -ne $Stamp)
{
    if (Test-Path $ZinkObj) { Remove-Item $ZinkObj -Recurse -Force }
    New-Item -ItemType Directory -Force $ZinkObj | Out-Null

    $Tarball = Get-Pinned "https://archive.mesa3d.org/mesa-$MesaVersion.tar.xz" $MesaSha256
    # Git for Windows tar treats C: as a remote host.
    & $Python -I -c "import sys, tarfile; tarfile.open(sys.argv[1]).extractall(sys.argv[2], filter='data')" $Tarball $ZinkObj
    if ($LASTEXITCODE -ne 0) { throw "could not extract $Tarball" }

    # Git can skip patches when it finds an enclosing checkout.
    $env:GIT_CEILING_DIRECTORIES = $ZinkObj
    foreach ($Patch in $Patches)
    {
        & git.exe -C $MesaSource apply --whitespace=nowarn $Patch.FullName
        if ($LASTEXITCODE -ne 0) { throw "patch does not apply: $($Patch.Name)" }
    }

    Set-Content $NativeFile $NativeLines
    Set-Content $StampFile $Stamp
}

foreach ($Target in $Targets)
{
    $BuildDir = Join-Path $ZinkObj ('build-' + $Target.Arch)
    if (-not (Test-Path (Join-Path $BuildDir 'build.ninja')))
    {
        Invoke-DevShell $Target.Arch "meson setup `"$BuildDir`" `"$MesaSource`" --native-file `"$NativeFile`" $MesaOptions"
    }
    Invoke-DevShell $Target.Arch "ninja -C `"$BuildDir`""
    Copy-Item (Join-Path $BuildDir 'src\gallium\targets\wgl\libgallium_wgl.dll') (Join-Path $Bin $Target.Directory) -Force
}
