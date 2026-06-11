# HTB CDSA - Sysmon Threat Detection Pack

Detection scripts and XML queries for [HTB Certified Defensive Security Analyst (CDSA)](https://academy.hackthebox.com/) modules.

Companion blog writeups: [sec-savvy.com CDSA journey](https://github.com/kismatkunwar89/writeups) - Module 3 notes and [Skill Assessment](https://github.com/kismatkunwar89/writeups/blob/main/_posts/2026-06-05-module-3-skill-assessment.md).

SPL hunting queries built alongside this journey: [spl-threat-hunting-library](https://github.com/kismatkunwar89/spl-threat-hunting-library).

Each module is self-contained with its own use cases, shared config, and detector scripts.

Each use case follows a **two-step workflow**:

1. **First-pass XML query** - paste into Event Viewer (*Filter Current Log -> XML ->
   Edit query manually*) to confirm the IOC is present in the log.
2. **PowerShell detector** - run against the `.evtx` for deep pivoting (process
   creation context, parent/commandline, user, hashes, timeline).

All detectors are **behavior-based and target-agnostic** - they key off *what is
happening* (unsigned DLL, CLR in a non-.NET process, memory-read access mask),
not hardcoded process names.

---

## Repository Structure

```
HTB-CDSA/
├── module3-finding-evil/
│   ├── 01-dll-hijack/
│   ├── 02-clr-injection/
│   ├── 03-credential-dumping/
│   ├── 04-strange-ppid/
│   └── _shared/
│       ├── Invoke-EvtxRecon.ps1
│       ├── baseline-eventlog-queries.xml
│       └── sysmonconfig.xml
└── README.md
```

---

## Module 3 - Finding Evil

### Prerequisite: Sysmon config (`module3-finding-evil/_shared/sysmonconfig.xml`)

Detection only works if the telemetry is collected. The shared config enables the
events these use cases depend on. Install / update on the target:

```cmd
Sysmon64.exe -accepteula -i _shared\sysmonconfig.xml   # first install
Sysmon64.exe -c _shared\sysmonconfig.xml               # update existing
```

Key events enabled:
- **Event ID 1** - ProcessCreate (pivot context for every use case)
- **Event ID 7** - ImageLoad (DLL hijack + CLR injection)
- **Event ID 10** - ProcessAccess (credential dumping) - `onmatch="exclude"` so
  ALL process access is logged, benign OS sources filtered out.

> The stock SwiftOnSecurity config ships Event 10 as an empty `include` block =
> logs nothing. That was changed to `exclude` here to actually capture it.

---

## Use Cases

### 01 - DLL Hijack
`01-dll-hijack/`
- **IOC:** unsigned DLL loaded from outside System32/SysWOW64 (and a trusted EXE
  copied to a writable dir alongside it).
- **First-pass anchor:** `Signed=false` (Event 7).
- **Detector** also covers the UAC-bypass trailing-space mocked directory trick.

### 02 - CLR Injection (execute-assembly / unmanaged PowerShell)
`02-clr-injection/`
- **IOC:** `clr.dll` / `clrjit.dll` loaded into a process that has no reason to
  run .NET (e.g. `spoolsv.exe`).
- **First-pass anchor:** CLR DLL paths (Event 7), **no suppression** - review the
  `Image` column manually; legit .NET hosts can be injection targets too.
- **Detector** uses spawn-vs-load timeline gap to spot runtime injection.

### 03 - Credential Dumping (LSASS / ProcessAccess)
`03-credential-dumping/`
- **IOC:** process opening another process's memory with a read mask
  (`0x1010` etc.), cross-user access, source from a writable path, or UNKNOWN in
  CallTrace.
- **First-pass anchor:** `EventID=10` + `GrantedAccess=0x1010`.
- **Detector** flags cross-user, writable-path, and injected-code access, then
  pivots to Event 1.

### 04 - Strange PPID / Process Injection
`04-strange-ppid/`
- **IOC:** trusted process (e.g. `WerFault.exe`) spawning `cmd.exe` or
  `powershell.exe` after `CreateRemoteThread` injection with empty
  `StartModule` / `StartFunction`.
- **First-pass anchor:** all Event ID 1 process creations (small log sets).
- **Detector** flags impossible parent-child pairs and correlates Event ID 8.

### Skill Assessment mapping

| Assessment question | Folder |
|---|---|
| Q1 DLL Hijacking | `01-dll-hijack/` |
| Q2–Q3 PowershellExec | `02-clr-injection/` |
| Q4–Q5 Dump | `03-credential-dumping/` |
| Q6 Strange PPID | `04-strange-ppid/` |

---

## Per-use-case workflow

```
1. Apply module3-finding-evil/_shared/sysmonconfig.xml on the target (once)
2. Open the .evtx (or live log) in Event Viewer
3. Paste <module>/<usecase>/1-first-pass-query.xml  -> confirm IOC hits exist
4. Edit $evtx path at top of <module>/<usecase>/2-detect.ps1
5. powershell -ExecutionPolicy Bypass -File <module>\<usecase>\2-detect.ps1
```

> **Note:** The PowerShell detector (`2-detect.ps1`) can be run directly against
> any `.evtx` without the XML first-pass step. The XML queries exist for large
> logs where pre-filtering in Event Viewer reduces volume before the script runs.
>
> **Warning when editing XML filters:** The XML queries are written to be
> deliberately broad. Do not tighten them to suppress noisy results - noise is
> expected and the PowerShell script handles triage. Over-filtering in XML risks
> removing the exact patterns that indicate an attack. When in doubt, widen the
> filter, never narrow it.

---

## Key XPath / Sysmon lessons baked in

- Event Viewer XPath supports **exact-match only** - no wildcards, no
  `contains()`/`starts-with()`, no field-to-field comparison (e.g. SourceUser !=
  TargetUser must be done in PowerShell).
- `!=` is deceptive on EventData (true if *any* Data node differs) - use
  `<Suppress>` to exclude.
- `band()` bitwise AND *is* supported (useful for GrantedAccess masks), but the
  hex-string coercion is environment-dependent - exact-match is more reliable.
- Sysmon `onmatch="include"` empty = log nothing; `onmatch="exclude"` empty = log
  everything.
- `SystemTime` in event XML is always UTC - derive the offset from the log's own
  events, not the analyst machine. (See `_shared/baseline-eventlog-queries.xml`.)

---

## `_shared/`
- `Invoke-EvtxRecon.ps1` - first-pass recon: validate path, sample XML fields,
  enumerate Event IDs, optionally dump one Event ID before running a detector.
- `sysmonconfig.xml` - Sysmon config enabling Events 1, 7, 10.
- `baseline-eventlog-queries.xml` - reference 4624 (logon) / 4907 (audit-policy
  change) queries with UTC-offset and timestamp-window notes.
