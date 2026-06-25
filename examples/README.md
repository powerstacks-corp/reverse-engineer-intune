# Example output

Real analyses the skill produced on a lab device, lightly sanitized: the device
name, tenant, GUIDs, certificate thumbprint, and user names have been replaced with
placeholders. The technical findings are unchanged. This is the kind of markdown the
skill writes out for you, screenshot placeholders and all.

- [last-check-in-analysis.md](last-check-in-analysis.md) — why a fresh "Last Check-in"
  in the Intune portal can be a lie. The timestamp is stamped when the OMA-DM session
  connects, not when policy applies, so it marches forward while CSP commands fail
  inside the same session. Tier 1 (forensic snapshot) only.
- [stuck-app-install-analysis.md](stuck-app-install-analysis.md) — an app Intune
  reported as `0x80070002` ("file not found") that was nothing of the sort. Cisco
  Secure Endpoint was injecting a DLL into every SYSTEM-context process the IME
  launched and killing it at load with `0xC0000142`, which the IME then relabeled as a
  missing file. Tier 1 plus targeted event-log and registry reads.
