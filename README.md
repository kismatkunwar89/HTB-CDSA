# Windows Threat Detection — Sysmon Hunting Pack

Three credential-theft / code-execution detection use cases, each built as a
**two-step workflow**:

1. **First-pass XML query** — paste into Event Viewer (*Filter Current Log → XML →
   Edit query manually*) to confirm the IOC is present in the log.
2. **PowerShell detector** — run against the `.evtx` for deep pivoting (process
   creation context, parent/commandline, user, hashes, timeline).

All detectors are **behavior-based and target-agnostic** — they key off *what is
happening* (unsigned DLL, CLR in a non-.NET process, memory-read access mask),
not hardcoded process names.

---

## Prerequisite: Sysmon config (`_shared/sysmonconfig.xml`)

Detection only works if the telemetry is collected. The shared config enables the
events these use cases depend on. Install / update on the target:

```cmd
Sysmon64.exe -accepteula -i _shared\sysmonconfig.xml   # first install
Sysmon64.exe -c _shared\sysmonconfig.xml               # update existing
```

Key events enabled:
- **Event ID 1** — ProcessCreate (pivot context for every use case)
- **Event ID 7** — ImageLoad (DLL hijack + CLR injection)
- **Event ID 10** — ProcessAccess (credential dumping) — `onmatch="exclude"` so
  ALL process access is logged, benign OS sources filtered out.

> The stock SwiftOnSecurity config ships Event 10 as an empty `include` block =
> logs nothing. That was changed to `exclude` here to actually capture it.

---

## Use Cases

### 01 — DLL Hijack
`01-dll-hijack/`
- **IOC:** unsigned DLL loaded from outside System32/SysWOW64 (and a trusted EXE
  copied to a writable dir alongside it).
- **First-pass anchor:** `Signed=false` (Event 7).
- **Detector** also covers the UAC-bypass trailing-space mocked directory trick.

### 02 — CLR Injection (execute-assembly / unmanaged PowerShell)
`02-clr-injection/`
- **IOC:** `clr.dll` / `clrjit.dll` loaded into a process that has no reason to
  run .NET (e.g. `spoolsv.exe`).
- **First-pass anchor:** CLR DLL paths (Event 7), **no suppression** — review the
  `Image` column manually; legit .NET hosts can be injection targets too.
- **Detector** uses spawn-vs-load timeline gap to spot runtime injection.

### 03 — Credential Dumping (LSASS / ProcessAccess)
`03-credential-dumping/`
- **IOC:** process opening another process's memory with a read mask
  (`0x1010` etc.), cross-user access, source from a writable path, or UNKNOWN in
  CallTrace.
- **First-pass anchor:** `EventID=10` + `GrantedAccess=0x1010`.
- **Detector** flags cross-user, writable-path, and injected-code access, then
  pivots to Event 1.

---

## Per-use-case workflow

```
1. Apply _shared/sysmonconfig.xml on the target (once)
2. Open the .evtx (or live log) in Event Viewer
3. Paste <usecase>/1-first-pass-query.xml  -> confirm IOC hits exist
4. Edit $evtx path at top of <usecase>/2-detect.ps1
5. powershell -ExecutionPolicy Bypass -File <usecase>\2-detect.ps1
```

---

## Key XPath / Sysmon lessons baked in

- Event Viewer XPath supports **exact-match only** — no wildcards, no
  `contains()`/`starts-with()`, no field-to-field comparison (e.g. SourceUser !=
  TargetUser must be done in PowerShell).
- `!=` is deceptive on EventData (true if *any* Data node differs) — use
  `<Suppress>` to exclude.
- `band()` bitwise AND *is* supported (useful for GrantedAccess masks), but the
  hex-string coercion is environment-dependent — exact-match is more reliable.
- Sysmon `onmatch="include"` empty = log nothing; `onmatch="exclude"` empty = log
  everything.
- `SystemTime` in event XML is always UTC — derive the offset from the log's own
  events, not the analyst machine. (See `_shared/baseline-eventlog-queries.xml`.)

---

## `_shared/`
- `sysmonconfig.xml` — Sysmon config enabling Events 1, 7, 10.
- `baseline-eventlog-queries.xml` — reference 4624 (logon) / 4907 (audit-policy
  change) queries with UTC-offset and timestamp-window notes.
