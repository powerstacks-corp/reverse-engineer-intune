# Reverse Engineer Intune

A Claude Code skill that investigates what Microsoft Intune actually does on a managed
Windows device, in the spirit of how Rudy Ooms reverse-engineers Intune internals, and
writes the findings up as an investigative blog post. You run it by telling Claude
"go rudy this <scenario>".

## What it does

It collects the evidence Intune leaves on the device (the Intune Management Extension
logs, the relevant registry, the MDM certificate state, scheduled tasks, services,
device join state, and the management event logs), then reasons over it to find the
real mechanism and any gap between what Intune reports and what the device is actually
doing. The output is a markdown post.

Everything it uses is free and built into Windows. The optional deeper tiers use free
tools (Sysinternals Procmon, the MIT-licensed ilspycmd decompiler). The only thing you
need is Claude Code itself.

## Requirements and footprint

- **Claude Code**, running on the device you want to analyze.
- **Most of it runs as a normal user.** Tier 1's forensic snapshot and the Tier 3 and Tier 4
  decompilers all read from locations a standard user can read, so they do not need elevation.
- **Some parts need administrator rights:**
    - Tier 1 captures most evidence as a standard user; run it elevated for the full picture
      (the IME registry hive, certificate private-key detail, and a few admin-only logs).
    - Tier 2 (Procmon live capture) requires administrator, Procmon loads a kernel driver.
    - Installing the .NET SDK (Tier 3) or the JDK (Tier 4) the first time may prompt for
      elevation.
- **Tier 4 is heavy.** Its toolchain (Ghidra plus a JDK) is roughly 1 GB, and the first run
  downloads Ghidra, a few hundred MB. The lighter tiers are small: Tier 3's ilspycmd is a few
  MB, and Tiers 1 and 2 add nothing.

## Install

Put this folder in your Claude Code skills directory, then start Claude Code:

    Windows:  %USERPROFILE%\.claude\skills\reverse-engineer-intune

## Use

On an Intune-managed Windows device, in an elevated Claude Code session:

    go rudy this last check-in

A colon after "this" is fine too: `go rudy this: last check-in`.

Claude runs the collector, analyzes the bundle, and writes the post.

## Scope

Run it on a device you control. Collection is read-only. See SKILL.md for the full
method, the toolchain tiers, and the techniques it draws on.
