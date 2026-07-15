<#
.SYNOPSIS
    Tier 3 (decompilation) helper for the Advanced Intune Troubleshooting skill. Decompiles the
    Intune Management Extension SideCar assemblies to C# so the analysis can read the
    actual code: hardcoded timers, session handlers, install paths. The deepest "rudy"
    move, used to PROVE a code-level claim you could otherwise only infer from logs.

.DESCRIPTION
    Uses ILSpy's free, MIT-licensed ilspycmd. Decompiles a whole IME assembly to one C#
    file (greppable), or a single fully-qualified type with -Type. Read-only: it reads
    the installed assemblies and writes C# source to OutputPath. Nothing on the device
    is modified.

    Requires the free .NET SDK (ilspycmd is a dotnet global tool). If the SDK is missing
    the script tells you the one-line install and stops. ilspycmd itself is installed
    automatically the first time.

.PARAMETER Assembly
    The IME assembly to decompile: a file name (matched in the IME folder), a full path,
    or "all" for every dll/exe in the IME folder. Defaults to the main agent assembly.
    Use ime-version.txt from the forensic bundle to pick the right one.

.PARAMETER Type
    Optional fully-qualified type name. Decompiles just that type (faster, targeted),
    for example a class you found referenced in the logs.

.PARAMETER OutputPath
    Where to write the decompiled C#. Defaults to a timestamped folder under %TEMP%.

.EXAMPLE
    .\Invoke-ImeDecompile.ps1 -Assembly Microsoft.Management.Services.IntuneWindowsAgent.exe
    Then grep the resulting .cs for the method or constant you are testing.
#>
[CmdletBinding()]
param(
    [string]$Assembly = 'Microsoft.Management.Services.IntuneWindowsAgent.exe',
    [string]$Type,
    [string]$OutputPath = (Join-Path $env:TEMP ("ImeDecompiled_" + (Get-Date -Format 'yyyyMMdd_HHmmss')))
)

$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$Message, [string]$Level = 'INFO') Write-Host ("[{0}] {1}" -f $Level, $Message) }

# 1. Locate the IME install dir
$imeDir = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Intune Management Extension'
if (-not (Test-Path $imeDir)) {
    throw "IME install dir not found: $imeDir. Is this an Intune-managed device with the Management Extension installed?"
}

# 2. Ensure the .NET SDK (needed to install/run ilspycmd)
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "The .NET SDK is required for ilspycmd and was not found. Install it (free):`n    winget install Microsoft.DotNet.SDK.8`nThen open a new terminal and run this again."
}
Write-Step ("dotnet SDK: " + (& dotnet --version))

# 3. Ensure ilspycmd (free, MIT) as a dotnet global tool
$ilspy = Join-Path $env:USERPROFILE '.dotnet\tools\ilspycmd.exe'
if (-not (Test-Path $ilspy)) {
    $existing = Get-Command ilspycmd -ErrorAction SilentlyContinue
    if ($existing) {
        $ilspy = $existing.Source
    } else {
        Write-Step "Installing ilspycmd (free, MIT-licensed) as a dotnet global tool..."
        & dotnet tool install -g ilspycmd | Out-Host
        if (-not (Test-Path $ilspy)) {
            $existing = Get-Command ilspycmd -ErrorAction SilentlyContinue
            if ($existing) { $ilspy = $existing.Source } else { throw "ilspycmd was not found after install. Check the 'dotnet tool install -g ilspycmd' output above." }
        }
    }
}
Write-Step ("ilspycmd: " + $ilspy)

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

# 4. Resolve the target assembly/assemblies
$targets = @()
if ($Assembly -eq 'all') {
    $targets = Get-ChildItem $imeDir -File | Where-Object { $_.Extension -in '.dll', '.exe' } | Select-Object -ExpandProperty FullName
    Write-Step ("Decompiling all {0} assemblies in the IME folder. This can take a while; targeting one assembly is usually faster." -f $targets.Count) 'WARN'
} else {
    $path = if (Test-Path $Assembly) { $Assembly } else { Join-Path $imeDir $Assembly }
    if (-not (Test-Path $path)) {
        throw "Assembly not found: $path. Pick the exact name from ime-version.txt, or pass -Assembly all."
    }
    $targets = @($path)
}

# 5. Decompile to greppable C#
foreach ($t in $targets) {
    $name = [IO.Path]::GetFileNameWithoutExtension($t)
    if ($Type) {
        $outFile = Join-Path $OutputPath ("{0}.{1}.cs" -f $name, ($Type -replace '[^\w.]', '_'))
        Write-Step "Decompiling type $Type from $name ..."
        & $ilspy "$t" -t "$Type" > $outFile
    } else {
        $outFile = Join-Path $OutputPath ("$name.cs")
        Write-Step "Decompiling $name ..."
        & $ilspy "$t" > $outFile
    }
    $kb = if (Test-Path $outFile) { [math]::Round((Get-Item $outFile).Length / 1KB, 1) } else { 0 }
    Write-Step ("  -> {0} ({1} KB)" -f $outFile, $kb)
}

Write-Host ""
Write-Host ("Decompiled source ready: {0}" -f $OutputPath)
Write-Host "Grep it for the method or constant you are after, for example:"
Write-Host '    Select-String -Path "' + $OutputPath + '\*.cs" -Pattern "OnSessionChange|28800000|RemoveExistingProducts"'
