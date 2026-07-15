# The Last Check-in Lie: a green timestamp is a dial tone, not a health check

> _Real output from the Advanced Intune Troubleshooting skill, lightly sanitized: the device name, tenant, GUIDs, certificate thumbprint, and user names have been replaced with placeholders. The technical findings are unchanged._

## TL;DR

The "Last Check-in" you stare at in the Intune portal is the moment the device
opened an OMA-DM session and got a reply from the service. That is all it proves.
It does not prove a single policy applied. On this device the check-in clock keeps
ticking forward every few hours while CSP commands quietly fail inside the very same
session. The cert is valid, the push channel is alive, the device is genuinely
talking to Intune, and it is still throwing 404s and failed app alerts on every sync.
Last Check-in is a dial tone. It tells you the phone is connected, not that anyone
on the other end did what you asked.

## The setup

The device is `CONTOSO-PC01`, Windows 11 Enterprise build 26200, Azure AD joined,
IME 1.101.111.0. Nothing about it looks broken. If you opened this object in the
portal you would see a recent Last Check-in and move on.

That is exactly the problem. A recent Last Check-in is the single most trusted, and
single most misread, field in the whole console. People treat it as "this device is
healthy and managed." It means nothing of the sort. So let us take the timestamp
apart and find out what actually sets it, and whether the reassurance it gives you
survives contact with the logs.

## The investigation

First, kill the obvious suspect. The classic Last Check-in horror story is an expired
MDM certificate: the device keeps reporting an old check-in because it can no longer
renew the cert that authenticates the session. Not here.

```
Subject       : CN=11111111-1111-1111-1111-111111111111
Issuer        : CN=Microsoft Intune MDM Device CA
Thumbprint    : A1B2C3D4E5F60718293A4B5C6D7E8F9012345678
NotAfter      : 2/19/2027 3:50:11 PM
HasPrivateKey : True
DaysToExpiry  : 252.9
```

Valid for another 252 days, private key present, TPM-backed. And it is the right
cert: the enrollment record points straight at that same thumbprint.

```
HKLM\SOFTWARE\Microsoft\Enrollments\AAAAAAAA-1111-2222-3333-444444444444
  EnrollmentType   = 0x6        (MDMDeviceWithAAD)
  ProviderID       = "MS DM Server"
  DMPCertThumbPrint = A1B2C3D4E5F60718293A4B5C6D7E8F9012345678
  AADTenantID      = 00000000-0000-0000-0000-000000000000
```

So this is a healthy enrollment with a healthy cert. Good. That means whatever the
Last Check-in shows, it is not lying about connectivity. It is connecting. The
question is what the connection actually buys you.

Two enrollments, not one. The EnterpriseMgmt task tree has two GUID folders, and the
registry explains why:

```
HKLM\...\Enrollments\AAAAAAAA...\LinkedEnrollment
  LinkedEnrollmentId = BBBBBBBB-5555-6666-7777-888888888888
  MMPCLocked = 1
  EnrollStatus = 3
  LastError = 0
```

`AAAAAAAA` is the real Intune MDM enrollment. `BBBBBBBB` is its linked
declared-configuration (MMP-C) enrollment. Both run their own OMA-DM sessions, both
are healthy. This is normal modern Windows behavior, not a fault, but it matters
because it means you have two streams of check-ins feeding the same portal field.

Now the part that sets the timestamp. The check-in is an OMA-DM session, and the
device logs exactly when one fires. Event 265 in the
`DeviceManagement-Enterprise-Diagnostics-Provider/Operational` channel:

```
1:50:05 PM  265  MDM Session: OMA-DM sessions triggered ... Account ID(BBBBBBBB-...)
1:21:16 PM  265  MDM Session: OMA-DM sessions triggered ... Account ID(AAAAAAAA-...)
11:27:18 AM 265  MDM Session: OMA-DM sessions triggered ... Account ID(AAAAAAAA-...)
10:00:04 AM 265  MDM Session: OMA-DM sessions triggered ... Account ID(BBBBBBBB-...)
 6:10:03 AM 265  MDM Session: OMA-DM sessions triggered ... Account ID(BBBBBBBB-...)
 4:29:05 AM 265  MDM Session: OMA-DM sessions triggered ... Account ID(AAAAAAAA-...)
```

A session every few hours, plus extra ones on demand. What kicks the on-demand ones?
The WNS push. The scheduled task that the push wakes is `PushLaunch`, and its last
run lines up to the second with the session:

```
EnterpriseMgmt\BBBBBBBB...\PushLaunch   LastRunTime 6/11/2026 1:20:53 PM  Result 0
EnterpriseMgmt\AAAAAAAA...\PushLaunch   LastRunTime 6/11/2026 1:20:54 PM  Result 0
```

And the push channel itself is live and unexpired:

```
HKLM\...\Enrollments\AAAAAAAA...\Push
  ChannelURI = https://wns2-xxxx.notify.windows.com/?token=...
  Status = 0
  DeviceChannel = 1
```

So the trigger chain is airtight: WNS push at 1:20:53, `PushLaunch` fires, OMA-DM
session at 1:20:57 and 1:21:16, server replies, Last Check-in advances to ~1:21 PM.
That is the timestamp. That is the whole of what it certifies.

Here is what happened in the seconds between those two session markers, in that same
1:21 PM check-in:

```
1:21:07 PM  404   MDM ConfigurationManager: Command failure status.
                   CSP URI: .../ADMXInstall/Receiver/Properties/Policy/FakePolicy/Version
                   Result: (The system cannot find the file specified.)
1:21:09 PM  1928  EnterpriseDesktopAppManagement CSP: An application status alert
                   failed to be sent ... MSI {cefaec57-33dc-4775-bfd2-561699357699}
                   Result: (0x82ac0204).
```

And it is not a one-off. Rewind to the 11:27 AM check-in and you get the same set,
including a second flavor of failure:

```
11:27:11 AM 404   .../ADMXInstall/.../FakePolicy/Version  (file not found)
11:27:12 AM 454   MDM ConfigurationManager: Command failure status.
                   CSP URI: .../Policy/Config/System/AllowOOBEUpdates
                   Result: (Unknown Win32 Error code: 0x82aa0002).
```

Every session, the same errors. The check-in clock never so much as flinches.

## The mechanism

"Last Check-in" is written from the OMA-DM session, not from the outcome of the
commands carried inside it. The flow is:

1. A timer (the `Poll` schedule under the enrollment) or a WNS push fires.
2. `PushLaunch` / the schedule starts an OMA-DM session (Event 265).
3. The device authenticates with the TPM-backed MDM device cert, opens the SyncML
   exchange, and the service responds.
4. That successful round-trip is the check-in. The portal stamps it.
5. Inside the session body, the individual CSP commands are processed one by one.
   Each one returns its own SyncML status. Some return 200. Some return the
   equivalent of 404 (`0x82aa0002` is OMA-DM's "node not found") or fail to post an
   app alert (`0x82ac0204`). These per-command results are logged as Event 404 / 454
   / 1928 and reported back to the service as status, but they do not move the
   check-in timestamp, because the check-in already happened at step 3.

The status field is set by the act of connecting, before, and independent of, the
work the connection implies. That is the same pattern Rudy keeps flagging across
Intune: a success marker stamped at the start of a flow, describing contact rather
than completion. Distrust any status that is written before the thing it appears to
vouch for.

A note on those errors, because honesty matters more than drama: not all of them are
real problems. The `ADMXInstall/FakePolicy/Version` 404 is a well-known benign probe
Intune does on every sync to test the ADMX path. `0x82aa0002` on `AllowOOBEUpdates`
is a node-not-found that is usually harmless. The failed MSI app alert is more
interesting and might be a genuinely stuck Win32/MSI deployment worth chasing. But
that distinction is exactly the point. The portal cannot tell the difference either.
Benign 404, harmless node miss, or a real app that will never install, all three
produce the identical green Last Check-in. The timestamp has no opinion about any of
them.

## The contradiction

Reported: a fresh Last Check-in, advancing every few hours and on every push,
implying "this device is managed and policy is flowing."

Actual: the device is connecting fine, but inside those connections CSP commands fail
on every single session. The thing the timestamp makes you assume (policy applied)
is not the thing the timestamp measures (a session connected). A healthy Last
Check-in and a device that is failing to apply configuration are not contradictory
states in Intune. They are the normal, expected, everyday coexistence that the field
is structurally incapable of distinguishing.

If you want device health, the Last Check-in column is the wrong place to look. You
have to read the session contents, the per-CSP status, the app and compliance state.
The timestamp only ever told you the line was open.

## How to reproduce on a lab device

1. Take any healthy AADJ + Intune device. Confirm a current MDM cert
   (`Get-ChildItem Cert:\LocalMachine\My | ? Issuer -match 'Intune MDM'`) and a live
   push channel (`Status = 0` under the enrollment `Push` key). The point is to start
   from a device that genuinely checks in.
2. Assign something that will fail at the CSP level but not kill the session. An MSI
   Win32 app that cannot install, or a policy targeting a node that does not exist on
   the SKU, both work. You want red inside the session, not a broken session.
3. Force a sync (Settings > Accounts > Access work or school > Info > Sync, or the
   `PushLaunch` task). Watch
   `DeviceManagement-Enterprise-Diagnostics-Provider/Operational` for Event 265 (the
   check-in) and `/Admin` for Event 404 / 454 / 1928 (the failures) in the same
   window.
4. Now look at the portal. Last Check-in is current. The device is "fine." The
   command that failed in step 2 is still failing. Repeat the sync and watch the
   timestamp march forward while the failure stays put.

## Open questions

- I read this entirely from the device side. I did not log into the portal for this
  tenant, so the claim "the portal shows a fresh Last Check-in" is inferred from the
  successful OMA-DM sessions and the live push channel, not observed on screen.
  Confirming the exact portal timestamp against Event 265 would close the loop.
- The enrollment UPN is a placeholder: `UPN = "user@contoso.com"`, and
  `dsregcmd` shows a failed PRT attempt for a different identity
  (`jdoe@contoso.com`, status `0xc004844c`) while the logged-on user is
  `auser@contoso.com`. Device-context OMA-DM authenticates with the TPM
  device cert, not the UPN, so none of this breaks the check-in, but it is a messy
  identity picture in this lab tenant and worth a separate look.
- The failed MSI app alert (`0x82ac0204`, ProductCode `{cefaec57-...}`) is the one
  in-session failure that might be a real stuck deployment rather than benign noise.
  Pulling the IME and `AppXDeploymentServer` logs for that ProductCode would settle
  whether it is cosmetic or a genuinely undeployable app.
- Tier used: Tier 1 (forensic snapshot only). The mechanism did not need Procmon or a
  decompile. If anyone disputes that the check-in is stamped before command
  processing, a Procmon capture of `omadmclient` plus a decompile of the session
  handler would nail the ordering exactly.
```
```

Collected non-elevated, so the IME registry hive and some private-key detail were not
captured. Nothing in the conclusion depends on them.
