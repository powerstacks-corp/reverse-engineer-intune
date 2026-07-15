---
name: intune-advanced-troubleshooting
description: >
  Investigate what Microsoft Intune actually does on a managed Windows device
  and write up the findings as a Rudy-Ooms-style investigative blog post. Trigger with
  "go rudy this <scenario>" or "go rudy this: <scenario>", "rudy <scenario>", or
  "troubleshoot intune <scenario>".
  Collects Intune Management Extension logs, registry, scheduled tasks, services, and
  certificates (Tier 1, no extra tools), and optionally a filtered Procmon trace
  (Tier 2) or a decompiled IME assembly (Tier 3), then explains the real mechanism and
  any gap between what Intune reports and what is actually happening on the box.
---

# Advanced Intune Troubleshooting ("go rudy this")

Investigate how a specific Intune operation works on a managed Windows device, the way
Rudy Ooms does on call4cloud.nl and the Patch My PC blog: read the evidence the device
leaves behind, find the gap between what Intune *reports* and what *actually happens*,
explain the underlying mechanism, and write it up as a blog post.

The user invokes this by saying "go rudy this <scenario>" (a colon after "this" is
fine too, "go rudy this: <scenario>"), "rudy <scenario>", or "troubleshoot intune
<scenario>". The deliverable is a markdown post in the investigative style described
under "Output" below.

## Scope and safety

- Run this on a **test device the user controls**, not a production fleet. The agent
  has shell access during collection.
- Collection is **read-only** by default: read logs, registry, certificates, task and
  service config. Do not modify device state unless the user explicitly asks you to
  reproduce a condition (e.g. expire a cert on a lab device).
- Never bundle or redistribute Sysinternals binaries (their license forbids it).
  Acquire Procmon from the official source at run time, or ask the user to place it.
- Everything this skill drives is free: built-in Windows tooling, Sysinternals (free to
  use), `ilspycmd` (MIT), and Ghidra (Apache-2.0). Keep it that way so the skill stays
  publicly usable.
- Most steps run as a normal user. Tier 1's deepest capture and Tier 2's Procmon need
  administrator rights, and the first .NET SDK or JDK install may prompt for elevation.
  Tell the user up front when a step needs elevation rather than letting it fail silently.
- Tier 4 is heavy: Ghidra plus a JDK is roughly 1 GB, and the first run downloads a few
  hundred MB. Warn the user before you kick it off, and only reach for it when the lighter
  tiers cannot answer.

## Working from a plain symptom

The user describes a symptom in plain language ("go rudy this: my PowerShell script takes
hours to run", "go rudy this: an app shows failed but it is actually installed"). You drive
everything from there. Do not make the user name files, assemblies, registry keys, or
tiers. That is your job, not theirs.

- **Escalate tiers yourself.** Run Tier 1 first. The moment the log and registry evidence
  leaves the actual mechanism unproven, escalate on your own (Tier 2 to watch it happen
  live, Tier 3 to read the IME's .NET code, Tier 4 to read native OS code) rather than stopping at a plausible guess or
  waiting to be asked. Going deep is the default when the lighter tier cannot close it.
- **Pick your own targets.** You do not need the user to tell you what to decompile or
  capture. The IME logs name the components involved (grep them for the manager, handler,
  and class names they mention), and the evidence map points at the subsystem. From those,
  choose which assembly to decompile and what term to grep for. Example: a script-timing
  question points at the SideCar script workload, so you decompile the SideCar agent
  assembly and grep its C# for the timer constant and the session-change handler, without
  being told to.
- **Say what you did.** In the writeup, name the tier you reached and why the lighter tiers
  could not answer. The user's prompt stays simple; your method stays explicit.

## Method

Work like an investigator, not a log dumper. For every run:

1. **State the question.** Turn the scenario into a falsifiable question, e.g. "Why does
   Intune show a recent last check-in when the device can no longer sync?"
2. **Form a hypothesis** from what you know about the subsystem before you read the data.
3. **Gather evidence** with the collector (see Toolchain). Build a single correlated
   **timeline** across logs + registry + tasks + certs around the window of interest.
4. **Find the mechanism.** Identify the exact process, code path, registry value, or
   certificate field that explains the behavior. Prefer the most specific cause you can
   prove over a plausible-sounding generality.
5. **Hunt the contradiction.** Rudy's signature move: where does Intune's reported state
   disagree with the device's real capability? Name it explicitly.
6. **Verify.** Cross-check the conclusion against a second signal. If you can cheaply
   reproduce or falsify it on the lab device, do so.
7. **Write it up** in the Output format. Flag anything you could not prove as an open
   question rather than asserting it.

## Rudy's techniques (the tricks)

Distilled from his posts. Reach for these in step 4 (mechanism) and step 5 (contradiction):

- **Reported vs. actual is the headline.** The whole genre is "Intune says X, the device
  actually does Y." Always hunt the gap (Last Check-in, silent cert-renewal failure).
- **Distrust a status written before the work it implies.** "Last check-in" is written
  from the server-response timestamp *before* any policy enforcement, so it proves
  contact, not management. When a success marker is set early in a flow, suspect it.
- **Find the persisted "last run" anchor to explain scheduling.** The SideCar
  `LastExecution` value under `HKLM\SOFTWARE\Microsoft\IntuneManagementExtension\SideCarPolicies\Scripts\Execution\<UserId>\<PolicyId>_<Version>`
  tells you whether a job is interval-gated or just event-triggered-on-arrival. Most
  "why didn't it run on time" mysteries live here.
- **Identify the owning engine first.** Policy/config flows through OMA-DM/CSP (shows as
  SyncML in the DeviceManagement event logs, woken by a WNS push, so the Sync button
  speeds it up). Apps/scripts/remediations flow through IME + SideCar, governed by local
  timers and untouched by Sync. Registry timer constants: `28800000` ms = 8h (PowerShell
  scripts), `3600000` ms = 1h (required apps).
- **Decompile the IME/SideCar assembly for the real logic.** `ilspycmd` on the SideCar
  binaries surfaces hardcoded timers and handlers like `OnSessionChange` ->
  `ProcessAppsOnSession` (why user-context scripts wait for logon) and install code paths.
- **When a break follows an OS/agent update, diff the binaries.** Compare working vs.
  broken DLL (e.g. `InstallService.dll` April vs. May), enumerate new feature flags, then
  cross-check the flag against the server-side OneSettings/flight JSON (e.g.
  `Sccinstallservice.json`, `FixInstallUnderSystemContext`) to see if it is merely present
  or actively enabled.
- **For installer-induced breakage, read the MSI action timeline.** `RemoveExistingProducts`
  sequenced after new files land can delete freshly-installed config; pair with
  binding-redirect / config-vs-assembly mismatches (`IDX12729`, `0x80131040`).
- **When the cloud says "sent" but nothing runs locally, check the OS delivery log first.**
  The WNS / Push Notification Platform operational log, Event IDs `1010` -> `1225` for IME's
  AUMID. Absence of the expected IDs is the proof (the signal in the silence). The WNS app
  registration lives in the PushNotifications registry hive and only rebuilds under SYSTEM.
- **For OAuth/provisioning handoffs, look for token-*parsing* errors, not auth errors.**
  Shell-Core log strings `crackIdToken` / `idTokenNotThreeParts` / `JSON parsing failure`
  mean a response-shape mismatch (HTML instead of a redirect), not a real auth failure,
  behind generic codes like `80004005`.
- **Compare stored identity to sent identity.** Read enrollment values (UPN/TenantID under
  `HKLM\SOFTWARE\Microsoft\Enrollments\{ID}`), then compare against the actual network
  request to catch stale-UPN/identity mismatches after a domain migration.
- **Decode generic error codes to specific meaning before theorizing** (`0x87D1041C`,
  `80004005`, `80180014`, `0x80180018` = MENROLL_E_USERLICENSE / Event 52 UserValidation,
  `IDX12729`).
- **Follow the provisioning handshake endpoint-by-endpoint** (`login.live.com/rst2`,
  `ztd.dds.microsoft.com`, the `x-device-token` header, `cloudassignedoobeconfig`, `ZTDID`),
  and separate "what configures the experience" from "what sets identity/ownership."
- **Build one timeline.** Timestamp-correlate logs + registry + events to find the *true*
  trigger, not the apparent one.

## Intune subsystem and evidence map

Where the evidence lives for the most common scenarios:

- **IME / Win32 apps / scripts / remediations:**
  `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\` (`IntuneManagementExtension.log`,
  `AgentExecutor.log`, `ClientHealth.log`, `Sensor.log`). Registry:
  `HKLM\SOFTWARE\Microsoft\IntuneManagementExtension`. The IME service is
  `Microsoft Intune Management Extension`; the SideCar assemblies live under
  `C:\Program Files (x86)\Microsoft Intune Management Extension\`.
- **Enrollment / MDM / sync (OMA-DM):** Event log
  `Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin` and
  `/Operational`. Registry: `HKLM\SOFTWARE\Microsoft\Enrollments\<GUID>`,
  `HKLM\SOFTWARE\Microsoft\Provisioning\OMADM`. Scheduled tasks under
  `\Microsoft\Windows\EnterpriseMgmt\<GUID>\` (the sync schedule).
- **MDM certificate:** `Cert:\LocalMachine\My`, issued by "Microsoft Intune MDM Device CA".
  Check `NotAfter`, the private key presence, and the renewal task. (This is the core of
  the Last Check-in scenario.)
- **Policies / config / ADMX:** `HKLM\SOFTWARE\Microsoft\PolicyManager\current\device`,
  `...\providers`. ADMX-ingested policy under the same tree.
- **Autopilot / ESP / provisioning:** `HKLM\SOFTWARE\Microsoft\Provisioning`,
  `...\Windows\Autopilot`, the `DeviceManagement-Enterprise-Diagnostics-Provider` and
  `Shell-Core` / `ESP` event logs, and IME ClientHealth during provisioning.

## Toolchain (tiers)

Start at Tier 1. Only escalate when the question needs a signal the prior tier cannot
give you. State in the writeup which tier you used.

- **Tier 1, forensic (no extra tools):** run `scripts/Collect-IntuneForensics.ps1` to
  snapshot logs, registry, tasks, services, IME version, and cert state into a bundle,
  then reason over it. Covers most log/registry/cert scenarios, including Last Check-in.
- **Tier 2, live capture (Procmon, free):** when you need to see file/registry/process
  activity as an operation runs. Drive Procmon from its CLI with a filter limited to
  `IntuneManagementExtension.exe`, `AgentExecutor`, `msiexec`, `powershell`, trigger the
  operation (e.g. force a sync), stop, and export to CSV. Built-in `pktmon` / `netsh
  trace` are free fallbacks for network-layer questions.
- **Tier 3, decompilation (ilspycmd, free, .NET only):** when the answer is in the IME's
  own MANAGED code. Run `scripts/Invoke-ImeDecompile.ps1` to decompile a SideCar assembly
  to C# (it installs the free, MIT-licensed ilspycmd automatically; it needs the free .NET
  SDK present and tells you the one-line install if it is missing). Choose the assembly
  yourself from the bundle's `ime-version.txt` and the class names the logs reference, or
  pass `-Type <fully.qualified.Name>`, then grep the output for the method or constant you
  are testing (`OnSessionChange`, a timer like `28800000`, the install or launch path) and
  quote the real C#. Use it to PROVE a code-level claim you could otherwise only infer, for
  example that a script delay is a hardcoded interval, or how the SideCar launches an
  installer into the machine session. **Once you are in the code, extract all the proof it
  offers.** Prove every code-level claim in your analysis from the source you already
  decompiled, not just the one that prompted the escalation. If a mechanism has more than
  one code-backed part (say, a hardcoded timer AND the `OnSessionChange` handler that gates
  it on user logon), quote each from source, rather than proving one from code and leaving
  its sibling as log or registry inference when the same assembly can settle both. **Limit: ilspycmd reads .NET only.** The native
  Windows OS components (the OMA-DM client `omadmclient.exe`, `dmenrollengine.dll`, the CSP
  handlers, where Last Check-in and policy processing actually live) are native C++ and
  cannot be decompiled this way. If a question lands there, say so plainly rather than
  forcing it. That is a native-decompiler job, which is Tier 4.
- **Tier 4, native decompilation (Ghidra, free):** for the native OS code Tier 3 cannot
  read, the OMA-DM client `omadmclient.exe`, `dmenrollengine.dll`, the CSP handlers, where
  Last Check-in, enrollment, and policy/CSP processing actually live. Run
  `scripts/Invoke-NativeDecompile.ps1 -Binary <name>` (for example `omadmclient.exe`). It
  installs a free JDK and Ghidra if missing, runs Ghidra's headless analyzer, and writes the
  decompiled pseudo-C. This is the heaviest, slowest tier and the genuine last resort: reach
  for it only when Tiers 1 to 3 cannot answer, and the first run downloads Ghidra (a few
  hundred MB). Microsoft public symbols load by default: the helper points Ghidra at the
  Microsoft symbol server, downloads the binary's PDB, and applies it during analysis, so
  functions come back with their real names (for example
  `Microsoft::Windows::MDM::OmadmClient::OmadmAccountManager::StoreServerLastTime`, with typed
  parameters), not `FUN_*`. This is what lets you read it like source and name the exact
  mechanism the way Rudy does. Finding the right code: grep the output for the function name
  you expect (`StoreServerLastTime`, `StoreServerLastAccessTime`) or pass `-FunctionFilter
  "<name substring>"` to export only matching functions. You can still pass `-StringFilter
  "<text>"` to anchor on a known log message, registry value, or CSP node path, which is the
  fallback when a binary has no public PDB (functions are then `FUN_*`); in that case also
  grep for Microsoft's internal source-file paths baked in as assert strings (for example
  `onecoreuap\admin\dm\omadm\omadmclient\lib\src\syncmlsession.cpp`). `-NoSymbols` skips the
  symbol download for offline runs. Read and quote the pseudo-C, but say plainly that native
  decompilation is lossier than .NET, so Tier 4 conclusions still carry some uncertainty even
  with names.

## Output

Write `<scenario>-analysis.md` as a blog post, in Rudy's voice: direct, a little wry,
mechanism-first, no filler. Structure:

- **Title** that names the surprising finding (e.g. "The Illusion of ...").
- **TL;DR** at the top: the conclusion in two or three sentences.
- **The setup:** what was observed and why it is surprising.
- **The investigation:** the timeline and the key evidence, with the exact log lines,
  registry values, or certificate fields that mattered (quote them).
- **The mechanism:** the precise reason, the code path, value, or field that explains it.
- **The contradiction:** reported state vs. actual capability, stated plainly.
- **Conclusion + how to reproduce:** steps to reproduce on a lab device.
- **Open questions:** anything you could not prove.

**Screenshot placeholders.** Rudy's posts lean on screenshots, and you cannot take them
yourself (the Intune portal, Registry Editor, Event Viewer, ILSpy, and Procmon are GUI
surfaces you have no eyes on). So mark where each one belongs and tell the reader exactly
how to capture it, using the specifics you already hold. At each spot insert a blockquote:

```
> [SCREENSHOT] caption: what it shows and why it matters here
> Capture: the exact tool, the path or query or filter, and what to highlight
```

Be precise, because you know the exact evidence. For example:

- > Capture: Registry Editor, go to HKLM\SOFTWARE\Microsoft\Enrollments\{ID}, screenshot the RenewErrorCode value.
- > Capture: Event Viewer, Applications and Services Logs > Microsoft > Windows > DeviceManagement-Enterprise-Diagnostics-Provider > Operational, filter to Event ID 265, screenshot the session rows and their times.
- > Capture: Intune portal, Apps > the app > Device install status, screenshot the row reporting 0x80070002.
- > Capture: open the decompiled .cs that Invoke-ImeDecompile.ps1 produced, screenshot the method showing the 28800000 timer.

For command-line evidence, give the exact command to run and screenshot (for example, run
Get-ChildItem on Cert:\LocalMachine\My filtered to the Intune MDM issuer and screenshot the
NotAfter and HasPrivateKey columns). Place a screenshot only where a visual genuinely earns
it, the contradiction, the smoking-gun log line, the key registry value, the decompiled
method, not on every paragraph.

Match the user's writing guidance for any public-facing prose (no em-dashes, avoid
AI-writing tells). Do not invent log lines or values; if you did not capture a signal,
say so and drop to a lower-confidence statement or escalate a tier.

## Validation mode

When the user asks to test against a known Rudy post, reproduce the scenario on the lab
device, run the analysis blind, then compare your conclusion to his. Report matches,
misses, and anything you found that he did not (or vice versa). The first target is the
Last Check-in / expired-MDM-certificate scenario.
