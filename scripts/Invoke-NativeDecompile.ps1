<#
.SYNOPSIS
    Tier 4 (native decompilation) helper for the Advanced Intune Troubleshooting skill. Decompiles
    native Windows OS binaries to pseudo-C with Ghidra, for the OS-level Intune internals
    that ilspycmd (Tier 3, .NET only) cannot read: the OMA-DM client, dmenrollengine, and
    the CSP handlers, where Last Check-in, enrollment, and policy/CSP processing live.

.DESCRIPTION
    Uses Ghidra's free, open-source headless analyzer. Installs a JDK and Ghidra into a
    local cache if they are missing. Read-only on the target: it reads the named system
    binary and writes decompiled C to OutputPath. This is the heaviest and slowest tier,
    a last resort when Tiers 1 to 3 cannot answer.

.PARAMETER Binary
    The native binary to decompile: a full path, or a bare file name resolved against
    System32 (for example omadmclient.exe, dmenrollengine.dll).

.PARAMETER FunctionFilter
    Optional case-insensitive substring. Only functions whose name contains it are exported.
    Microsoft symbols load by default, so functions are named (StoreServerLastTime); this is
    the primary way to isolate the code you want, for example -FunctionFilter "ServerLast".

.PARAMETER StringFilter
    Optional case-insensitive substring. Only functions that reference a defined string
    containing this text are exported. Anchor on a known log message, registry value name, or
    CSP node path. This is the fallback for the rare binary with no public PDB, where the
    functions come back as FUN_* and you have no names to filter on.

.PARAMETER NoSymbols
    Skip the Microsoft symbol download (offline runs, or msdl unreachable). Functions then
    come back as FUN_*; use -StringFilter to find the right code.

.PARAMETER OutputPath
    Folder for the decompiled C and the Ghidra log. Defaults to a timestamped %TEMP% folder.

.NOTES
    Free tooling only: Ghidra (NSA, Apache-2.0) and a JDK. Heavier than the .NET tier; the
    first run downloads Ghidra (a few hundred MB), and the first run per binary downloads its
    PDB from the Microsoft symbol server (cached locally). Analysis can take several minutes.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Binary,
    [string]$FunctionFilter,
    [string]$StringFilter,
    [switch]$NoSymbols,
    [string]$OutputPath = (Join-Path $env:TEMP ("NativeDecompiled_" + (Get-Date -Format 'yyyyMMdd_HHmmss')))
)

$ErrorActionPreference = 'Stop'
function Write-Step { param([string]$Message, [string]$Level = 'INFO') Write-Host ("[{0}] {1}" -f $Level, $Message) }

# Resolve the target binary
$binPath = if (Test-Path $Binary) { (Resolve-Path $Binary).Path } else { Join-Path $env:WINDIR ("System32\" + $Binary) }
if (-not (Test-Path $binPath)) { throw "Binary not found: $binPath. Pass a full path, or a System32 file name like omadmclient.exe." }
Write-Step "Target: $binPath"

$cache = Join-Path $env:LOCALAPPDATA 'PowerStacks\rudy-tier4'
New-Item -ItemType Directory -Path $cache -Force | Out-Null

# 1. Ensure a JDK (Ghidra needs Java 17 or newer)
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    Write-Step "No Java found. Installing Microsoft OpenJDK 21 (free) via winget..."
    winget install --id Microsoft.OpenJDK.21 --silent --accept-source-agreements --accept-package-agreements | Out-Host
    $jhome = Get-ChildItem 'C:\Program Files\Microsoft\jdk-*' -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    if ($jhome) { $env:JAVA_HOME = $jhome.FullName; $env:PATH = (Join-Path $jhome.FullName 'bin') + ';' + $env:PATH }
    if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
        throw "Java still not on PATH after install. Open a new terminal and run again, or install a JDK 17+ manually."
    }
}
Write-Step "Java is available."

# 2. Ensure Ghidra
$ghidraDir = Get-ChildItem $cache -Directory -Filter 'ghidra_*' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $ghidraDir) {
    Write-Step "Ghidra not in cache. Fetching the latest release from GitHub..."
    $rel = Invoke-RestMethod 'https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest' -Headers @{ 'User-Agent' = 'rudy' }
    $asset = $rel.assets | Where-Object { $_.name -match '^ghidra_.*\.zip$' } | Select-Object -First 1
    if (-not $asset) { throw "Could not find a Ghidra release zip on the latest release." }
    $zip = Join-Path $cache $asset.name
    Write-Step ("Downloading {0} (~{1} MB)..." -f $asset.name, [math]::Round($asset.size / 1MB))
    Invoke-WebRequest $asset.browser_download_url -OutFile $zip
    Write-Step "Extracting (this takes a minute)..."
    Expand-Archive -Path $zip -DestinationPath $cache -Force
    Remove-Item $zip -Force
    $ghidraDir = Get-ChildItem $cache -Directory -Filter 'ghidra_*' -ErrorAction SilentlyContinue | Select-Object -First 1
}
if (-not $ghidraDir) { throw "Ghidra install failed." }
$headless = Join-Path $ghidraDir.FullName 'support\analyzeHeadless.bat'
if (-not (Test-Path $headless)) { throw "analyzeHeadless.bat not found under $($ghidraDir.FullName)." }
Write-Step ("Ghidra: " + $ghidraDir.Name)

# 3. Run headless analysis + the decompile-export post-script
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$projDir = Join-Path $OutputPath 'ghidra-proj'
New-Item -ItemType Directory -Path $projDir -Force | Out-Null
$outCs = Join-Path $OutputPath ("{0}.c" -f [IO.Path]::GetFileNameWithoutExtension($binPath))

$postScript = Join-Path $PSScriptRoot 'ghidra\ExportDecompiled.java'
if (-not (Test-Path $postScript)) { throw "Post-script not found: $postScript" }
$scriptDir = Split-Path $postScript
$scriptName = Split-Path $postScript -Leaf

# Microsoft public symbols: configured by a pre-script so native functions come back named
# (StoreServerLastTime) instead of FUN_*. On by default; -NoSymbols skips it (offline runs).
$preArgs = @()
if (-not $NoSymbols) {
    $symbolCache = Join-Path $cache 'symbols'
    New-Item -ItemType Directory -Path $symbolCache -Force | Out-Null
    $preArgs = @('-preScript', 'EnableMsSymbols.java', $symbolCache)
    Write-Step "Symbols: ON. First run for a given binary downloads its PDB from msdl.microsoft.com (cached under $symbolCache)."
} else {
    Write-Step "Symbols: OFF (-NoSymbols). Functions will be FUN_*; anchor with -StringFilter."
}

$headlessArgs = @(
    $projDir, 'rudyproj',
    '-import', $binPath,
    '-scriptPath', $scriptDir
) + $preArgs + @(
    '-postScript', $scriptName, $outCs
)
if ($FunctionFilter) { $headlessArgs += $FunctionFilter } elseif ($StringFilter) { $headlessArgs += '' }
if ($StringFilter) { $headlessArgs += $StringFilter }
$headlessArgs += '-deleteProject'

$logOut = Join-Path $OutputPath 'ghidra.out.log'
$logErr = Join-Path $OutputPath 'ghidra.err.log'
Write-Step "Running Ghidra headless analysis. This can take several minutes for a large binary..."
$proc = Start-Process -FilePath $headless -ArgumentList $headlessArgs -NoNewWindow -Wait -PassThru -RedirectStandardOutput $logOut -RedirectStandardError $logErr
Write-Step ("Ghidra exit code: " + $proc.ExitCode)

Write-Host ""
if (Test-Path $outCs) {
    Write-Host ("Decompiled C ready: {0} ({1} KB)" -f $outCs, [math]::Round((Get-Item $outCs).Length / 1KB, 1))
    Write-Host "Grep it for the function or string you are after. Logs: $logOut / $logErr"
} else {
    Write-Host "No .c output produced. Read $logErr and $logOut to see why (often a Java or analysis error)."
}
