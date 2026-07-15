# Advanced Intune Troubleshooting ("go rudy this")

A Claude Code skill that investigates what Microsoft Intune *actually* does on a managed
Windows device, in the spirit of how Rudy Ooms digs into Intune internals on
call4cloud.nl and the Patch My PC blog, and writes the findings up as an investigative
blog post.

You run it by describing a symptom in plain language. Claude does the rest: it picks the
evidence to collect, escalates through progressively deeper tooling on its own, finds the
gap between what Intune *reports* and what the device *actually does*, proves the
mechanism from real evidence (down to decompiled code when needed), and produces a
finished markdown writeup.

```
go rudy this last check-in
go rudy this: my PowerShell script takes hours to run
rudy an app shows failed but it is actually installed
troubleshoot intune why required apps install late
```

A colon after "this" is fine (`go rudy this: <scenario>`). All four trigger forms do the
same thing.

---

## Table of contents

- [What it can do](#what-it-can-do)
- [How a run works](#how-a-run-works)
- [The deliverable](#the-deliverable-the-writeup)
- [The investigative method](#the-investigative-method)
- [The four-tier toolchain (the core)](#the-four-tier-toolchain)
  - [Tier 1: forensic snapshot](#tier-1--forensic-snapshot-no-extra-tools)
  - [Tier 2: live capture](#tier-2--live-capture-procmon)
  - [Tier 3: managed decompilation](#tier-3--managed-net-decompilation-ilspycmd)
  - [Tier 4: native decompilation](#tier-4--native-decompilation-ghidra--microsoft-symbols)
- [Tool-and-tier reference table](#tool-and-tier-reference-table)
- [What the Tier 1 bundle contains](#what-the-tier-1-bundle-contains)
- [Requirements, elevation, and footprint](#requirements-elevation-and-footprint)
- [Scope, safety, and licensing](#scope-safety-and-licensing)
- [Where the evidence lives (subsystem map)](#where-the-evidence-lives-subsystem-map)
- [The analytical techniques it uses](#the-analytical-techniques-it-uses)
- [Validation mode](#validation-mode)
- [Repository layout](#repository-layout)

---

## What it can do

Given a one-line symptom, the skill can:

- **Collect the full forensic picture** an Intune-managed device leaves behind: the
  Intune Management Extension (IME) logs, the relevant registry hives, the MDM
  certificate state, the EnterpriseMgmt scheduled tasks, the management services, the
  device join state, the management event-log channels, and the IME version and assembly
  inventory, all into one analyzable bundle.
- **Build a single correlated timeline** across logs, registry, tasks, certificates, and
  events to find the *true* trigger of a behavior rather than the apparent one.
- **Watch an operation happen live** with a filtered Procmon capture when static evidence
  cannot prove the mechanism.
- **Read the IME's own managed (.NET) code** by decompiling the SideCar assemblies to C#,
  to prove a code-level claim (a hardcoded timer, a session handler, an install path)
  that logs can only imply.
- **Read the native OS code** behind enrollment, OMA-DM sync, Last Check-in, and CSP
  processing by decompiling Windows system binaries to pseudo-C with Ghidra, with
  Microsoft's public symbols applied so the functions come back with their real names.
- **Name the contradiction** in Rudy's signature style: where Intune's reported state
  disagrees with the device's actual capability.
- **Write it up** as a finished, mechanism-first blog post with quoted evidence and
  precise screenshot-capture instructions.
- **Validate itself** against a known Rudy post: reproduce the scenario, analyze blind,
  and compare conclusions.

It does **not** require you to name files, assemblies, registry keys, or tiers. You give
the symptom; the skill chooses the targets and escalates the tooling itself.

---

## How a run works

1. You give a plain-language symptom.
2. Claude turns it into a falsifiable question and forms a hypothesis from what it knows
   about the subsystem.
3. It runs **Tier 1** (the forensic collector) and reasons over the bundle, building a
   timeline around the window of interest.
4. If the static evidence cannot close the question, Claude **escalates on its own**:
   Tier 2 to watch the operation live, Tier 3 to read the IME's .NET code, Tier 4 to read
   the native OS code. Going deeper is the default when a lighter tier cannot prove the
   mechanism; it does not stop at a plausible guess or wait to be asked.
5. It picks its own targets (which assembly to decompile, which term to grep, which
   binary to disassemble) from the component names the logs reference.
6. It writes the analysis, naming which tier it reached and why the lighter tiers could
   not answer.

---

## The deliverable (the writeup)

The output is `<scenario>-analysis.md`, written in Rudy's voice (direct, a little wry,
mechanism-first, no filler), with this structure:

- **Title** that names the surprising finding (for example "The Illusion of a Recent
  Check-in").
- **TL;DR** at the top: the conclusion in two or three sentences.
- **The setup:** what was observed and why it is surprising.
- **The investigation:** the timeline and key evidence, with the exact log lines,
  registry values, or certificate fields that mattered, quoted.
- **The mechanism:** the precise process, code path, value, or field that explains it.
- **The contradiction:** reported state vs. actual capability, stated plainly.
- **Conclusion + how to reproduce:** steps to reproduce on a lab device.
- **Open questions:** anything that could not be proven.

Because the agent cannot take screenshots of GUI surfaces (the Intune portal, Registry
Editor, Event Viewer, ILSpy, Procmon), it marks where each screenshot belongs and gives
exact capture instructions, for example:

```
> [SCREENSHOT] caption: the MDM cert expired before the reported check-in
> Capture: Registry Editor, HKLM\SOFTWARE\Microsoft\Enrollments\{ID}, screenshot the RenewErrorCode value
```

Public-facing prose follows the no-em-dash, no-AI-tells writing guidance. The skill does
not invent log lines or values: if a signal was not captured, it says so and either drops
to a lower-confidence statement or escalates a tier.

---

## The investigative method

Every run follows the same seven steps (it works like an investigator, not a log dumper):

1. **State the question** as something falsifiable.
2. **Form a hypothesis** about the subsystem before reading the data.
3. **Gather evidence** with the collector and build one correlated timeline.
4. **Find the mechanism:** the exact process, code path, registry value, or certificate
   field that explains the behavior. Prefer the most specific provable cause.
5. **Hunt the contradiction:** where reported state disagrees with real capability.
6. **Verify** against a second signal; reproduce or falsify on the lab device if cheap.
7. **Write it up,** flagging anything unproven as an open question.

---

## The four-tier toolchain

Start at Tier 1. Escalate only when the question needs a signal the prior tier cannot
give. The writeup always states which tier was used.

| Tier | Purpose | Tool | License | Elevation | Footprint |
|------|---------|------|---------|-----------|-----------|
| 1 | Forensic snapshot of the evidence the device leaves behind | Built-in Windows tooling (`reg`, `dsregcmd`, `Get-WinEvent`, cert store, scheduled-task and service queries) | Built-in | Normal user (more with admin/SYSTEM) | None |
| 2 | Watch file/registry/process activity as an operation runs | Sysinternals **Procmon** (network fallback: built-in `pktmon` / `netsh trace`) | Free (not redistributed) | Administrator (kernel driver) | Small |
| 3 | Read the IME's own **managed (.NET)** code | **ilspycmd** (ILSpy) as a dotnet global tool | MIT | Normal user (SDK install may prompt once) | A few MB |
| 4 | Read the **native** OS code (enrollment, OMA-DM, CSP) | **Ghidra** headless + a **JDK**, with **Microsoft public symbols** | Apache-2.0 (Ghidra) | Normal user (JDK install may prompt once) | ~1 GB |

### Tier 1 — forensic snapshot (no extra tools)

**Script:** `scripts/Collect-IntuneForensics.ps1`
**Tool:** built into Windows. Nothing is downloaded or installed.
**What it is for:** snapshot the logs, registry, certificate, tasks, services, and event
channels, then reason over them. This covers most log/registry/certificate scenarios,
including the canonical Last Check-in case.

Parameters:

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `-OutputPath` | `%TEMP%\RudyForensics_<timestamp>` | Folder the bundle is written to |
| `-EventLogDays` | `7` | Days of event-log history to pull |
| `-MaxEventsPerChannel` | `2000` | Cap on events per channel, to keep the bundle readable |

It is **read-only** (it never modifies device state) and uses only built-in tooling. It
runs as a normal user and captures more when elevated (administrator, or SYSTEM via
Intune) because the IME registry hive, the certificate private-key detail, and a few
admin-only logs need elevation. See [the bundle contents](#what-the-tier-1-bundle-contains)
for everything it produces. Always start the analysis at the bundle's `summary.md`.

### Tier 2 — live capture (Procmon)

**Tool:** Sysinternals **Process Monitor** (Procmon), free to use. There is no script: the
agent drives Procmon from its command line.
**What it is for:** when you need to *see* file, registry, and process activity as an
operation runs, rather than infer it from after-the-fact logs.

How it is driven: acquire Procmon from the official Sysinternals source at run time (it is
never bundled or redistributed, the license forbids that), apply a filter limited to the
processes that matter (`IntuneManagementExtension.exe`, `AgentExecutor`, `msiexec`,
`powershell`), trigger the operation (for example force a sync), stop the capture, and
export to CSV for analysis.

**Network-layer fallback:** the built-in `pktmon` and `netsh trace` are free fallbacks
when the question is about network traffic rather than local file/registry activity.

**Elevation:** administrator is required, Procmon loads a kernel driver.

### Tier 3 — managed (.NET) decompilation (ilspycmd)

**Script:** `scripts/Invoke-ImeDecompile.ps1`
**Tool:** **ilspycmd**, the free, MIT-licensed command-line ILSpy decompiler, run as a
dotnet global tool.
**What it is for:** when the answer is in the IME's own managed code. It decompiles the
Intune Management Extension SideCar assemblies to C# so the analysis can read the actual
logic: hardcoded timers, session handlers, install paths. This is the move that *proves* a
code-level claim you could otherwise only infer from logs (for example that a script delay
is a hardcoded interval, or how the SideCar launches an installer into the machine
session).

Parameters:

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `-Assembly` | `Microsoft.Management.Services.IntuneWindowsAgent.exe` | The assembly to decompile: a file name (resolved in the IME folder), a full path, or `all` for every dll/exe in the IME folder |
| `-Type` | (none) | Optional fully-qualified type name; decompiles just that type (faster, targeted) |
| `-OutputPath` | `%TEMP%\ImeDecompiled_<timestamp>` | Where the decompiled C# is written |

Requirements and behavior:

- Requires the **free .NET SDK** (ilspycmd is a dotnet global tool). If the SDK is
  missing, the script prints the one-line install (`winget install Microsoft.DotNet.SDK.8`)
  and stops. **ilspycmd itself is installed automatically** the first time.
- Read-only: it reads the installed assemblies and writes C# to `-OutputPath`. Nothing on
  the device is modified.
- Pick the assembly from the bundle's `ime-version.txt` and the class names the logs
  reference, then grep the output for the method or constant you are testing, for example:

  ```powershell
  Select-String -Path "<OutputPath>\*.cs" -Pattern "OnSessionChange|28800000|RemoveExistingProducts"
  ```

- **Once in the code, extract all the proof it offers.** If a mechanism has more than one
  code-backed part (say a hardcoded timer *and* the `OnSessionChange` handler that gates it
  on user logon), quote each from source rather than proving one from code and leaving its
  sibling as inference.
- **Limit: .NET only.** The native Windows OS components (the OMA-DM client
  `omadmclient.exe`, `dmenrollengine.dll`, the CSP handlers, where Last Check-in and policy
  processing actually live) are native C++ and cannot be decompiled this way. That is a
  Tier 4 job.

### Tier 4 — native decompilation (Ghidra + Microsoft symbols)

**Script:** `scripts/Invoke-NativeDecompile.ps1`
**Ghidra automation:** `scripts/ghidra/EnableMsSymbols.java` (pre-script) and
`scripts/ghidra/ExportDecompiled.java` (post-script).
**Tools:** **Ghidra** (NSA, Apache-2.0) headless analyzer, a **JDK** (Microsoft OpenJDK 21,
installed via winget if Java is missing), and **Microsoft's public symbol server**.
**What it is for:** the native OS code Tier 3 cannot read, the OMA-DM client, the
enrollment engine, and the CSP handlers, where Last Check-in, enrollment, and policy/CSP
processing actually live. This is the heaviest, slowest tier and a genuine last resort:
reach for it only when Tiers 1 to 3 cannot answer.

Parameters:

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `-Binary` (required) | (none) | The native binary: a full path, or a bare name resolved against `System32` (for example `omadmclient.exe`, `dmenrollengine.dll`) |
| `-FunctionFilter` | (none) | Case-insensitive substring; export only functions whose name contains it (for example `ServerLast`). The primary way to isolate code, since symbols name the functions |
| `-StringFilter` | (none) | Case-insensitive substring; export only functions that reference a defined string containing this text. Anchor on a known log message, registry value, or CSP node path. The fallback when a binary has no public PDB and names are `FUN_*` |
| `-NoSymbols` | off | Skip the Microsoft symbol download (offline runs, or msdl unreachable) |
| `-OutputPath` | `%TEMP%\NativeDecompiled_<timestamp>` | Folder for the decompiled `.c` and the Ghidra logs |

How it works:

- Ensures a **JDK** (installs Microsoft OpenJDK 21 via winget if `java` is absent), then
  ensures **Ghidra** (downloads the latest release from GitHub into a local cache at
  `%LOCALAPPDATA%\PowerStacks\rudy-tier4` on first use).
- Runs Ghidra's headless analyzer (`analyzeHeadless.bat`) to import the binary and
  decompile it.
- **Microsoft public symbols load by default.** The `EnableMsSymbols.java` pre-script
  registers `https://msdl.microsoft.com/download/symbols/` as a *trusted* symbol server and
  caches PDBs locally (under `...\rudy-tier4\symbols`). The first run for a given binary
  downloads its PDB and applies it during analysis, so functions come back with their real
  names (for example
  `Microsoft::Windows::MDM::OmadmClient::OmadmAccountManager::StoreServerLastTime`, with
  typed parameters) instead of `FUN_*`. This is what lets you read it like source and name
  the exact mechanism.
- The `ExportDecompiled.java` post-script decompiles the matching functions to pseudo-C
  and writes `<binary>.c` (plus `ghidra.out.log` / `ghidra.err.log`). It honors the name
  and string filters and, when a string filter is used, annotates each function with the
  strings it references.
- Finding the right code: grep the output for the function name you expect
  (`StoreServerLastTime`, `StoreServerLastAccessTime`) or pass `-FunctionFilter`. For a
  binary with no public PDB, use `-StringFilter` and also grep for Microsoft's internal
  source-file paths baked in as assert strings (for example
  `onecoreuap\admin\dm\omadm\omadmclient\lib\src\syncmlsession.cpp`).

**Footprint and caveats:** the toolchain (Ghidra plus a JDK) is roughly 1 GB, the first
run downloads Ghidra (a few hundred MB), and analysis can take several minutes for a large
binary. Native decompilation is lossier than .NET, so Tier 4 conclusions carry some
uncertainty even with names, and the writeup says so.

---

## Tool-and-tier reference table

| Tool | Tier | Role | License / source | Installed by the skill? |
|------|------|------|------------------|--------------------------|
| `reg`, `dsregcmd`, `Get-WinEvent`, cert store, scheduled-task / service / CIM queries | 1 | Snapshot logs, registry, cert, tasks, services, events, join state | Built into Windows | n/a (built-in) |
| Sysinternals **Procmon** | 2 | Live file/registry/process trace | Free, Sysinternals (never redistributed) | No, acquired at run time or placed by the user |
| `pktmon` / `netsh trace` | 2 | Network-layer fallback trace | Built into Windows | n/a (built-in) |
| **ilspycmd** (ILSpy) | 3 | Decompile IME/SideCar managed assemblies to C# | MIT | Yes, as a dotnet global tool (needs the free .NET SDK) |
| .NET SDK | 3 | Host for ilspycmd | Microsoft, free | No, the script prints the one-line winget install if missing |
| **Ghidra** headless | 4 | Decompile native OS binaries to pseudo-C | Apache-2.0 (NSA) | Yes, downloaded to a local cache on first use |
| **JDK** (Microsoft OpenJDK 21) | 4 | Run Ghidra | Free | Yes, via winget if Java is missing |
| **Microsoft public Symbol Server** (msdl.microsoft.com) | 4 | Apply real function names (PDBs) during native analysis | Microsoft, public | Yes, configured by the pre-script; PDBs cached locally |

---

## What the Tier 1 bundle contains

`Collect-IntuneForensics.ps1` writes a single folder containing:

| Path | Contents |
|------|----------|
| `summary.md` | Read this first. Device, join state, the MDM-cert verdict (the Last Check-in tell), a map of the bundle, and analysis pointers (where to find OMA-DM last contact, SideCar `LastExecution`, and the reported-vs-actual comparison) |
| `ime-logs\` | The IME logs from `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\` (`IntuneManagementExtension.log`, `AgentExecutor.log`, `ClientHealth.log`, `Sensor.log`, and the rest). The primary timeline |
| `registry\*.reg` | `reg export` of `IntuneManagementExtension`, `Enrollments`, `Provisioning` (includes `OMADM`), `PolicyManager\current\device`, and `EnterpriseResourceManager` |
| `mdm-certificate.txt` | The Intune MDM device certificate(s): Subject, Issuer, Thumbprint, NotBefore, NotAfter, HasPrivateKey, DaysToExpiry, and an Expired flag |
| `localmachine-my-certs.txt` | All `LocalMachine\My` certs (Subject, Issuer, NotAfter, HasPrivateKey, Thumbprint) for context |
| `dsregcmd-status.txt` | Full `dsregcmd /status` device join state |
| `scheduled-tasks-enterprisemgmt.txt` | The `\Microsoft\Windows\EnterpriseMgmt\*` tasks (the sync schedule): State, LastRunTime, NextRunTime, LastTaskResult |
| `services.txt` | The management services: `IntuneManagementExtension`, `dmwappushservice`, `DmEnrollmentSvc`, `wlidsvc`, `WpnService` (State, StartMode, StartName, PathName) |
| `ime-version.txt` | The IME agent file version plus an inventory of every DLL in the IME folder with versions. The reference for choosing a Tier 3 assembly |
| `eventlogs\*.csv` | Up to nine management channels (see below). **Absence is evidence:** a channel with no events in the window is logged as such |
| `system-info.txt` | OS caption, version, build, computer name, domain, install date, last boot |
| `collection.log` | Per-step log of the collection itself, including any access that failed for lack of elevation |

Event channels captured (`-EventLogDays` window, `-MaxEventsPerChannel` cap):

- `DeviceManagement-Enterprise-Diagnostics-Provider/Admin` and `/Operational`
- `AAD/Operational`
- `User Device Registration/Admin`
- `ModernDeployment-Diagnostics-Provider/Autopilot` and `/Diagnostics`
- `Shell-Core/Operational`
- `PushNotification-Platform/Operational`
- `AppXDeploymentServer/Operational`

---

## Requirements, elevation, and footprint

- **Claude Code**, running on the device you want to analyze.
- **Most of it runs as a normal user.** Tier 1's snapshot and the Tier 3 / Tier 4
  decompilers all read from locations a standard user can read.
- **Elevation matrix:**

  | Step | Elevation |
  |------|-----------|
  | Tier 1 (snapshot) | Normal user captures most; **admin or SYSTEM** for the full picture (IME registry hive, cert private-key detail, admin-only logs) |
  | Tier 2 (Procmon) | **Administrator** (kernel driver) |
  | Tier 3 (ilspycmd) | Normal user; the **first .NET SDK install** may prompt for elevation |
  | Tier 4 (Ghidra) | Normal user; the **first JDK install** may prompt for elevation |

- **Footprint:** Tiers 1 and 2 add nothing on disk. Tier 3's ilspycmd is a few MB. **Tier
  4 is heavy:** Ghidra plus a JDK is roughly 1 GB, the first run downloads Ghidra (a few
  hundred MB), and the first run per binary downloads its PDB. The skill warns before
  kicking off Tier 4.

---

## Scope, safety, and licensing

- Run this on a **test device you control**, not a production fleet. The agent has shell
  access during collection.
- **Collection is read-only by default.** It reads logs, registry, certificates, task and
  service config. It does not modify device state unless you explicitly ask it to
  reproduce a condition on a lab device (for example expire a cert).
- **Never bundle or redistribute Sysinternals binaries** (their license forbids it).
  Procmon is acquired from the official source at run time, or placed by the user.
- **Everything the skill drives is free:** built-in Windows tooling, Sysinternals (free to
  use), `ilspycmd` (MIT), Ghidra (Apache-2.0), and a free JDK. Microsoft's public symbol
  server is public. The skill is intended to stay publicly usable, keep it free-only.
- The skill tells you up front when a step needs elevation, rather than letting it fail
  silently.

---

## Where the evidence lives (subsystem map)

The skill chooses targets from this map; it is summarized here so you can follow the
reasoning.

- **IME / Win32 apps / scripts / remediations:**
  `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\`;
  registry `HKLM\SOFTWARE\Microsoft\IntuneManagementExtension`; service
  `Microsoft Intune Management Extension`; SideCar assemblies under
  `C:\Program Files (x86)\Microsoft Intune Management Extension\`.
- **Enrollment / MDM / sync (OMA-DM):** event log
  `DeviceManagement-Enterprise-Diagnostics-Provider/Admin` and `/Operational`; registry
  `HKLM\SOFTWARE\Microsoft\Enrollments\<GUID>` and `...\Provisioning\OMADM`; scheduled
  tasks under `\Microsoft\Windows\EnterpriseMgmt\<GUID>\` (the sync schedule).
- **MDM certificate:** `Cert:\LocalMachine\My`, issued by "Microsoft Intune MDM Device CA",
  check `NotAfter`, private-key presence, and the renewal task. The core of the Last
  Check-in scenario.
- **Policies / config / ADMX:** `HKLM\SOFTWARE\Microsoft\PolicyManager\current\device` and
  `...\providers`.
- **Autopilot / ESP / provisioning:** `HKLM\SOFTWARE\Microsoft\Provisioning`,
  `...\Windows\Autopilot`, the `DeviceManagement-Enterprise-Diagnostics-Provider` and
  `Shell-Core` / ESP event logs, and IME ClientHealth during provisioning.

Two registry anchors worth knowing: SideCar
`...\IntuneManagementExtension\SideCarPolicies\Scripts\Execution\<UserId>\<PolicyId>_<Version>\LastExecution`
tells you whether a job is interval-gated or event-triggered; and the OMA-DM `AcctInfo`
blob (`ServerLastSuccessTime`) under `...\Provisioning\OMADM\Accounts` is the device's real
last contact time. Useful timer constants from the IME code: `28800000` ms = 8h (PowerShell
scripts), `3600000` ms = 1h (required apps).

---

## The analytical techniques it uses

Distilled from Rudy's posts, these are the moves the skill reaches for when finding the
mechanism and the contradiction:

- **Reported vs. actual is the headline.** Always hunt the gap ("Intune says X, the device
  does Y").
- **Distrust a status written before the work it implies.** "Last check-in" is written from
  the server-response timestamp before any policy enforcement, so it proves contact, not
  management.
- **Find the persisted "last run" anchor** (SideCar `LastExecution`) to explain scheduling.
- **Identify the owning engine first.** Policy/config flows through OMA-DM/CSP (SyncML in the
  DeviceManagement logs, woken by a WNS push, sped up by the Sync button); apps/scripts/
  remediations flow through IME + SideCar (local timers, untouched by Sync).
- **Decompile the IME/SideCar assembly for the real logic** (Tier 3): timers and handlers
  like `OnSessionChange` -> `ProcessAppsOnSession`.
- **When a break follows an update, diff the binaries** and cross-check new feature flags
  against the server-side OneSettings/flight JSON.
- **For installer-induced breakage, read the MSI action timeline** (`RemoveExistingProducts`
  sequencing; binding-redirect mismatches like `IDX12729`, `0x80131040`).
- **When the cloud says "sent" but nothing runs, check the OS delivery log** (WNS /
  PushNotification-Platform, Event IDs `1010` -> `1225`). Absence is the proof.
- **For OAuth/provisioning handoffs, look for token-parsing errors** (`crackIdToken`,
  `idTokenNotThreeParts`, JSON parsing failure) behind generic codes like `80004005`.
- **Compare stored identity to sent identity** (UPN/TenantID under
  `HKLM\SOFTWARE\Microsoft\Enrollments\{ID}`) to catch stale-UPN mismatches.
- **Decode generic error codes** (`0x87D1041C`, `80180014`, `0x80180018` =
  MENROLL_E_USERLICENSE, `IDX12729`) before theorizing.
- **Build one timeline.** Timestamp-correlate logs + registry + events to find the true
  trigger.

---

## Validation mode

When asked to test against a known Rudy post, the skill reproduces the scenario on the lab
device, runs the analysis blind, then compares its conclusion to his, reporting matches,
misses, and anything it found that he did not (or vice versa). The first target is the Last
Check-in / expired-MDM-certificate scenario.

---

## Repository layout

```
intune-advanced-troubleshooting/
  SKILL.md                              the skill definition (full method, tiers, techniques, output spec)
  README.md                             this file
  scripts/
    Collect-IntuneForensics.ps1         Tier 1: read-only forensic snapshot -> a bundle folder
    Invoke-ImeDecompile.ps1             Tier 3: decompile IME/SideCar .NET assemblies to C# (ilspycmd)
    Invoke-NativeDecompile.ps1          Tier 4: decompile native OS binaries to pseudo-C (Ghidra)
    ghidra/
      EnableMsSymbols.java              Tier 4 pre-script: register the Microsoft public symbol server (trusted) + local cache
      ExportDecompiled.java             Tier 4 post-script: decompile matching functions to C, with name/string filters
  examples/                             sanitized sample output the skill produced on a lab device
    last-check-in-analysis.md           why a fresh "Last Check-in" can be a lie (Tier 1)
    stuck-app-install-analysis.md       an app reported "file not found" that was really Cisco Secure Endpoint (Tier 1+)
```

See [examples/](examples/) for full sample output, and `SKILL.md` for the authoritative
method, the full set of techniques, and the output specification.
