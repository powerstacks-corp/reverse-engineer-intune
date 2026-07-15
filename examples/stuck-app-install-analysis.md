# The Install That Never Was: How Intune Turns 0xC0000142 Into "File Not Found"

> _Real output from the Advanced Intune Troubleshooting skill, lightly sanitized: the device name, tenant, GUIDs, certificate thumbprint, and user names have been replaced with placeholders. The technical findings are unchanged._

## TL;DR

An Adobe Acrobat Pro install was "stuck" in Intune, and the admin was chasing MSI
ProductCode `{cefaec57-33dc-4775-bfd2-561699357699}` because the portal reported the app
failing with `0x80070002` ("the system cannot find the file specified"). Nothing was
missing. The content downloaded and extracted fine, the installer process started fine,
and then every process the IME launches in the machine (Session 0) context died at loader
init with `0xC0000142` (STATUS_DLL_INIT_FAILED). The IME has no return-code mapping for
`0xC0000142`, so it quietly relabels it `0x80070002` and ships that lie to the service.
The ProductCode the admin was hunting appears in exactly zero log lines, because the
detection script that would have evaluated it never lived long enough to run.

Tier used: Tier 1 (forensic snapshot) plus targeted event-log and registry reads. The one
unproven link is named in Open Questions and needs a Tier 2 Procmon trace to close.

## The setup

Device `CONTOSO-PC01`, Windows 11 Enterprise 26200, IME `1.101.111.0`, Azure AD joined to
tenant "Contoso". The MDM certificate is healthy (valid until Feb 2027, private
key present), so the device is talking to Intune perfectly well. This is not a sync problem.
OMA-DM is fine. The only thing broken is apps.

In the portal: Adobe Acrobat Pro, required install, failing. Error code `0x80070002`. To
any sane admin that means a missing file or a wrong path, and the natural next move is to
go verify the detection rule, which is an MSI ProductCode:
`{cefaec57-33dc-4775-bfd2-561699357699}`. So you go looking for that product code on the
box. And you find nothing. It is not in the registry, not in the IME logs, not in the MSI
database. It is as if the device never heard of it.

That absence is the first clue, not a dead end.

## The investigation

The app is policy `CCCCCCCC-9999-0000-1111-222222222222`, name decoded from the toast
base64 in `AppWorkload.log` (`QWRvYmUgQWNyb2JhdCBQcm8=` = "Adobe Acrobat Pro"). Walking the
log for that policy, the whole lifecycle is in one tight window at `18:25:59`.

First, detection. The IME drops a PowerShell detection script and runs it through
AgentExecutor:

```
"...\agentexecutor.exe" -powershellDetection "...\CCCCCCCC..._1.ps1" ... 3600 "C:\Windows\System32\WindowsPowerShell\v1.0" 0 ...
[Win32App] SideCarScriptDetectionManager Launch powershell executor in machine session
[Win32App] SideCarScriptDetectionManager Create proxy process successfully.
[Win32App] SideCarScriptDetectionManager process id = 10668
[Win32App] SideCarScriptDetectionManager Powershell execution got lpExitCode: 0 lastWin32Error: 0
[Win32App] SideCarScriptDetectionManager Powershell ExitCode: -1073741502
[Win32App] Checked Powershell script exitCode: -1073741502 ... result of applicationDetected: False
[Win32App][DetectionActionHandler] ... resulted in action status: Success and detection state: NotDetected.
```

`-1073741502` is `0xC0000142`. The detection PowerShell did not return "not installed". It
returned "I could not initialize". The IME treats any non-zero detection exit as
NotDetected, so it concludes the app is missing and proceeds to install.

Then the install. The command is PSAppDeployToolkit v4:

```
[Win32App] ===Step=== InstallBehavior RegularWin32App, Intent 3 ... 
Invoke-AppDeployToolkit.exe -DeploymentType Install -DeployMode Silent
[Win32App] SetCurrentDirectory: C:\Windows\IMECache\CCCCCCCC-9999-0000-1111-222222222222_1
[Win32App] Launch Win32AppInstaller in machine session
[Win32App] lastWin32Error 0 after CreateProcess
[Win32App] Create installer process successfully.
[Win32App] process id = 15660
[Win32App] Installer process timeout milliseconds: 3600000.
[Win32App] Installation is done, collecting result
[Win32App] lpExitCode 3221225794
[Win32App] hResultFromWin32 -2147024574
[Win32App] Set EnforcementStateMessage.ErrorCode -2147024574
[Win32App] Admin did NOT set mapping for lpExitCode: 3221225794 of app: CCCCCCCC-9999-0000-1111-222222222222
[Win32App] Setting enforcementState as: Error with lpExitCode: 3221225794 without mapping
```

Read that carefully, because the IME is telling on itself. `CreateProcess` succeeds. The
content is present (`C:\Windows\IMECache\CCCCCCCC..._1`, freshly unzipped a few lines
earlier). The process runs for about 1.7 seconds and exits with `lpExitCode 3221225794`,
which is `0xC0000142` again. Then the IME computes `hResultFromWin32 -2147024574`, which is
`0x80070002`, ERROR_FILE_NOT_FOUND, and sets that as the error code it reports. It even
admits there is no mapping for the real exit code and that it is bucketing it into a
generic Error.

So both the install and the detection died the same way: `0xC0000142`. This is not Adobe.
Counting every machine-session launch in the log:

```
      6 SideCarScriptDetectionManager Powershell ExitCode: -1073741502
      1 SideCarScriptRequirementManager Powershell ExitCode: -1073741502
      1 lpExitCode 3221225794
```

Seven script launches across multiple apps (Adobe, Foxit, VS Code, ZoomIt, and others),
one installer launch, every single one `0xC0000142`, zero successes. Whatever this is, it
kills everything the SideCar starts in the machine session.

The control case is in `AgentExecutor.log`. A Proactive Remediation ran a PowerShell script
the same day and it worked:

```
PowerShell path is C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
[Executor] created powershell with process id 16780
Powershell exit code is 0
write output done. output = Hello World !
```

Same machine, same powershell.exe, same agent. Exit 0. The difference is context: the
remediation ran in the logged-on user's session, the app install and its detection ran "in
machine session", which is Session 0 as SYSTEM. Session 0 is where everything dies.

Now the ruling-out pass, because `0xC0000142` has a short list of usual suspects:

- AppLocker: configured but `AuditOnly` for every collection, and the rules are placeholder
  junk (`%OSDRIVE%\ThisWillBeBlocked.dll`, `%OSDRIVE%\ThisWillBeBlocked.exe`) plus an empty
  ManagedInstaller collection. No `8004`/`8007` enforced-block events. It is not blocking
  anything.
- WDAC / Config CI: also auditing, not enforcing. The CodeIntegrity/Operational log has
  `3076` audit entries ("would have been prevented if... enforced") but no `3077` enforced
  blocks. The MSI/Script channel logs `8028` audit, no `8029`. Audit mode allows.
- AppInit_DLLs: empty, `LoadAppInit_DLLs=0` in both the native and WOW6432Node hives. Not it.
- Session 0 desktop heap: `SharedSection=1024,20480,768`, the stock default. Not shrunk.
- A crash: no Application Error `1000`/`1001` WER record for these processes. `0xC0000142`
  here is a clean loader abort, not an exception. That is the fingerprint of a DLL's
  `DllMain` returning FALSE during process initialization.

A `DllMain` returning FALSE, hitting only Session 0 / SYSTEM-launched processes, uniformly,
while user-session launches succeed, points at something injecting a user-mode DLL into new
processes that then fails to initialize in the non-interactive context. There is exactly one
product on this box that does that: **Cisco Secure Endpoint 7.2.7** (the AMP connector),
installed under `C:\Program Files\Cisco\AMP\7.2.7` with its full module set (`tetra`,
`cefw`, `scriptid`, `elam`, `heuristic`, `ioc`). It is live: its `cscm.exe` shows up loading
DLLs in the CodeIntegrity log. Secure Endpoint's exploit prevention and script control work
by injecting into processes, and that is the kind of component that turns into a
`STATUS_DLL_INIT_FAILED` when its injected DLL cannot stand up inside a Session 0 child.

## The mechanism

The IME's SideCar runs Win32 app installs and their PowerShell detection/requirement scripts
as SYSTEM in the machine session. It launches them through a proxy process
(`Create proxy process successfully`) into Session 0. Something on this device injects a
user-mode DLL into those newly created processes, and in the Session 0 / non-interactive
context that DLL's initialization fails, so the loader aborts the whole process before its
entry point runs. The process therefore exits with `0xC0000142`, STATUS_DLL_INIT_FAILED:
the documented meaning is literally "initialization of the dynamic link library failed; the
process is terminating abnormally."

Because the process dies during init, the actual installer (`Invoke-AppDeployToolkit.exe`)
never gets to run a single line, and the detection script never gets to evaluate the MSI
ProductCode it was written to check. The app is forever NotDetected, so the IME forever
re-installs it, and the install forever dies the same way. The retry cadence is the
ordinary one: `checkinReason = MaintenanceTimer`, the hourly app evaluation, and the GRS
anchor is wiped on each pass (`[GRSManager] Reset GRS value for app: CCCCCCCC...`), so there
is not even a backoff to slow the loop down. After each failure the content is purged
(`removing content from cache ...CCCCCCCC..._1.bin`) and re-downloaded next hour. Stuck, by
construction.

## The contradiction

Intune reports Adobe Acrobat Pro as failed with `0x80070002`, "the system cannot find the
file specified." The device's reality is that the file was found, downloaded, unzipped, and
launched successfully, and then the process was killed at DLL-init time with `0xC0000142`.
Those two error codes share nothing. The `0x80070002` is not a measurement, it is a default
the IME invents when it meets an exit code it has no mapping for, and it says so in its own
log: `Admin did NOT set mapping for lpExitCode: 3221225794 ... Setting enforcementState as:
Error ... without mapping`.

So the admin is sent to look for a missing file and a suspect ProductCode, when the truth is
a process-injection DLL aborting SYSTEM-context launches. The ProductCode
`{cefaec57-33dc-4775-bfd2-561699357699}` appearing in zero log lines is not a mystery once
you see this: the detection script that names it dies at `0xC0000142` before it can run, so
the device never records the product code at all. The silence is the evidence.

## Conclusion and how to reproduce

Adobe was never the problem and neither was its ProductCode. Every Win32 app on this device
that relies on a script detection rule or a SYSTEM-context installer is in the same hourly
failure loop, all of them mislabeled `0x80070002`. Fix the thing that kills Session 0
launches (here, the prime suspect is Cisco Secure Endpoint's injected component, which wants
an exclusion or a version that initializes cleanly in non-interactive processes) and every
one of these apps will install on the next MaintenanceTimer with no Intune-side change.

To reproduce on a lab device:

1. Enroll a Windows 11 box in Intune and assign a required Win32 app that uses a PowerShell
   script detection rule and a SYSTEM-context install (PSAppDeployToolkit is a good stand-in).
2. Install an endpoint-security agent that injects a user-mode DLL into new processes and
   put it in a state where that DLL fails to initialize in Session 0 (a misapplied exploit
   prevention or script-control policy is the realistic trigger).
3. Watch `AppWorkload.log`: the detection PowerShell and the installer will both return
   `lpExitCode 3221225794` / `-1073741502` (`0xC0000142`), and the IME will report
   `0x80070002` to the service.
4. Confirm the headline: search every IME log and the registry for the app's detection
   ProductCode. It will be absent, because the script never ran.
5. To prove the gap is purely a reporting artifact, run the exact same detection script and
   the same installer interactively in the user session (as the remediation did here). They
   succeed, which means nothing is missing and the `0x80070002` was never real.

## Open questions

- The one link I have not directly proven is which DLL aborts the process. The evidence is
  circumstantial but strong: clean loader abort (`0xC0000142`, no WER), Session 0 only,
  universal, while a user-session run succeeds, with Cisco Secure Endpoint as the only
  injecting agent present and active. Closing it is a Tier 2 job: a Procmon trace filtered
  to the install PID, watching the Load Image events and reading the last module loaded
  before the process exits, or a quick test with Secure Endpoint's protection paused on the
  lab box. If the installs immediately succeed with the agent paused, the case is closed.
- Whether the same injection also explains the `3033`/`3076` CodeIntegrity churn on this box
  or that is unrelated audit noise from Git and Cisco's own binaries.
- Whether adding an explicit IME return-code mapping for `3221225794` would at least make
  the portal tell the truth. It would not fix the install, but it would stop sending admins
  to hunt for files that were never missing.
