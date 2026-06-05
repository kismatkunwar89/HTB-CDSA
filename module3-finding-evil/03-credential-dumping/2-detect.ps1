# =============================================================================
# detect-process-access.ps1
# Pivots from Sysmon Event ID 10 (ProcessAccess) hits to full attack context.
# Pairs with querybeforelsass.xml (the GrantedAccess=0x1010 query that worked).
#
# AGNOSTIC: anchors on the memory-read access MASK, not on lsass.exe or any
# process name. Catches credential dumping against ANY target process.
#
# Flow:
#   1. Find Event 10 with credential-dump masks (0x1010 and common variants)
#   2. Show SourceImage / TargetImage / SourceUser / TargetUser / CallTrace
#   3. Flag cross-user access (SourceUser != TargetUser)
#   4. Flag sources from writable/unusual paths
#   5. Flag UNKNOWN in CallTrace (injected / reflective code)
#   6. Pivot to Event ID 1 - who spawned the tool, commandline, parent, hash
#
# Usage: powershell -ExecutionPolicy Bypass -File .\detect-process-access.ps1
# =============================================================================

# Step 0 - EVTX path (change per engagement)
$evtx = 'C:\Logs\Dump\LsassDump.evtx'

# Step 0b - Credential-dump / injection access masks (the working query used 0x1010)
# These all contain PROCESS_VM_READ (0x10) = ability to read another process memory.
$dumpMasks = @('0x1010','0x1410','0x1438','0x143a','0x147a','0x1fffff','0x1f3fff')

# =============================================================================
# Step 1 - Find Event 10 with credential-dump masks (mirrors the working XML)
# =============================================================================
"=== Process Access with Memory-Read Masks (Sysmon ID 10) ==="

$hits = Get-WinEvent -Path $evtx -FilterXPath "*[System[EventID=10]]" -ErrorAction SilentlyContinue |
ForEach-Object {
    try {
        $x = [xml]$_.ToXml()
        $d = $x.Event.EventData.Data
        $mask = ($d | Where-Object { $_.Name -eq 'GrantedAccess' }).'#text'

        if ($dumpMasks -contains $mask.ToLower()) {
            [pscustomobject]@{
                TimeCreated       = $_.TimeCreated
                SourceProcessGuid = ($d | Where-Object { $_.Name -eq 'SourceProcessGuid' }).'#text'
                SourceImage       = ($d | Where-Object { $_.Name -eq 'SourceImage'       }).'#text'
                SourceUser        = ($d | Where-Object { $_.Name -eq 'SourceUser'        }).'#text'
                TargetImage       = ($d | Where-Object { $_.Name -eq 'TargetImage'       }).'#text'
                TargetUser        = ($d | Where-Object { $_.Name -eq 'TargetUser'        }).'#text'
                GrantedAccess     = $mask
                CallTrace         = ($d | Where-Object { $_.Name -eq 'CallTrace'         }).'#text'
            }
        }
    } catch { }
}

if (-not $hits) {
    "No credential-dump access masks found. Try widening `$dumpMasks or run plain EventID=10 to see actual masks."
    return
}

"Total credential-dump access events: $($hits.Count)"
""
$hits | Sort-Object TimeCreated |
    Select-Object TimeCreated,
        @{N='SourceProcess'; E={Split-Path $_.SourceImage -Leaf}},
        @{N='TargetProcess'; E={Split-Path $_.TargetImage -Leaf}},
        SourceUser, TargetUser, GrantedAccess |
    Format-Table -AutoSize

# =============================================================================
# Step 2 - Full detail per hit (SourceImage, TargetImage, CallTrace)
# =============================================================================
"" ; "=== Full Detail ==="
$hits | Sort-Object TimeCreated | Format-List

# =============================================================================
# Step 3 - Cross-user access (SourceUser != TargetUser)
# LSASS runs as SYSTEM. A normal user account reading it = abnormal.
# =============================================================================
"" ; "=== Cross-User Access (SourceUser != TargetUser) ==="
$crossUser = $hits | Where-Object { $_.SourceUser -and $_.TargetUser -and $_.SourceUser -ne $_.TargetUser }
if (-not $crossUser) { "None found." }
else {
    "*** SUSPICIOUS - source account differs from target account ***"
    $crossUser | Select-Object TimeCreated,
        @{N='SourceProcess'; E={Split-Path $_.SourceImage -Leaf}},
        SourceUser, TargetUser, GrantedAccess | Format-Table -AutoSize
}

# =============================================================================
# Step 4 - Source from writable/unusual location
# Legit tools live in System32 / Program Files, not Downloads / Temp / Desktop.
# =============================================================================
"" ; "=== Source from Writable/Unusual Location ==="
$writable = $hits | Where-Object { $_.SourceImage -match '\\Users\\|\\Temp\\|\\AppData\\|\\Downloads\\|\\Desktop\\|\\ProgramData\\' }
if (-not $writable) { "None found." }
else {
    "*** SUSPICIOUS - tool running from user-writable path ***"
    $writable | Select-Object TimeCreated, SourceImage, SourceUser, GrantedAccess | Format-List
}

# =============================================================================
# Step 5 - CallTrace UNKNOWN (injected / reflectively loaded code)
# =============================================================================
"" ; "=== CallTrace Anomalies (UNKNOWN memory) ==="
$injected = $hits | Where-Object { $_.CallTrace -and $_.CallTrace -match 'UNKNOWN' }
if (-not $injected) { "None found." }
else {
    "*** SUSPICIOUS - call originates from unbacked memory ***"
    $injected | Select-Object TimeCreated,
        @{N='SourceProcess'; E={Split-Path $_.SourceImage -Leaf}}, CallTrace | Format-List
}

# =============================================================================
# Step 6 - Pivot to Event ID 1 for process creation context
# Who spawned the tool? What commandline? What parent? What hash?
# =============================================================================
$targets = $hits.SourceProcessGuid | Where-Object { $_ } | Select-Object -Unique
"" ; "=== Process Creation Context (Sysmon ID 1) ==="

$procHits = Get-WinEvent -Path $evtx -FilterXPath "*[System[EventID=1]]" -ErrorAction SilentlyContinue |
ForEach-Object {
    try {
        $x = [xml]$_.ToXml()
        $d = $x.Event.EventData.Data
        $pg = ($d | Where-Object { $_.Name -eq 'ProcessGuid' }).'#text'
        if ($targets -contains $pg) {
            [pscustomobject]@{
                TimeCreated       = $_.TimeCreated
                ProcessGuid       = $pg
                Image             = ($d | Where-Object { $_.Name -eq 'Image'             }).'#text'
                CommandLine       = ($d | Where-Object { $_.Name -eq 'CommandLine'       }).'#text'
                ParentImage       = ($d | Where-Object { $_.Name -eq 'ParentImage'       }).'#text'
                ParentCommandLine = ($d | Where-Object { $_.Name -eq 'ParentCommandLine' }).'#text'
                User              = ($d | Where-Object { $_.Name -eq 'User'              }).'#text'
                IntegrityLevel    = ($d | Where-Object { $_.Name -eq 'IntegrityLevel'    }).'#text'
                Hashes            = ($d | Where-Object { $_.Name -eq 'Hashes'            }).'#text'
            }
        }
    } catch { }
}

if (-not $procHits) { "No process creation events found (source may have started before logging began)." }
else {
    foreach ($p in ($procHits | Sort-Object TimeCreated)) {
        "--- $($p.Image) ---"
        $p | Format-List
        "    Access events from this process:"
        $hits | Where-Object { $_.SourceProcessGuid -eq $p.ProcessGuid } |
            Select-Object TimeCreated, TargetImage, GrantedAccess, SourceUser, TargetUser |
            Format-Table -AutoSize
    }
}

# =============================================================================
# Step 7 - Final summary
# =============================================================================
"" ; "=== FINAL SUMMARY ==="
"Credential-dump access events : $($hits.Count)"
"Cross-user access             : $(@($crossUser).Count)"
"From writable paths           : $(@($writable).Count)"
"Injected (UNKNOWN CallTrace)  : $(@($injected).Count)"

# =============================================================================
# Step 8 - Probable attacker (weighted IOC scoring)
# Each IOC adds weight. Higher score = higher confidence it's the dumper.
#   +3  GrantedAccess is a known dump mask
#   +2  SourceImage from user-writable path
#   +2  SourceUser != TargetUser (cross-user memory access)
#   +2  UNKNOWN in CallTrace (shellcode / reflective code)
#   +1  TargetImage matches known credential store (lsass, lsaiso, winlogon)
# Score >= 5 = high confidence | Score >= 3 = suspicious
# =============================================================================
"" ; "=== PROBABLE ATTACKER (Weighted IOC Score) ==="

$scored = $hits | ForEach-Object {
    $score = 0
    $reasons = @()

    if ($dumpMasks -contains $_.GrantedAccess.ToLower()) {
        $score += 3
        $reasons += "DumpMask(+3)"
    }
    if ($_.SourceImage -match '\\Users\\|\\Temp\\|\\AppData\\|\\Downloads\\|\\Desktop\\|\\ProgramData\\') {
        $score += 2
        $reasons += "WritablePath(+2)"
    }
    if ($_.SourceUser -and $_.TargetUser -and $_.SourceUser -ne $_.TargetUser) {
        $score += 2
        $reasons += "CrossUser(+2)"
    }
    if ($_.CallTrace -match 'UNKNOWN') {
        $score += 2
        $reasons += "UnknownCallTrace(+2)"
    }
    if ($_.TargetImage -match 'lsass|lsaiso|winlogon') {
        $score += 1
        $reasons += "CredentialTarget(+1)"
    }

    $_ | Add-Member -NotePropertyName Score   -NotePropertyValue $score              -PassThru -Force |
         Add-Member -NotePropertyName Reasons -NotePropertyValue ($reasons -join ' | ') -PassThru -Force
}

$topHits = $scored | Where-Object { $_.Score -ge 3 } | Sort-Object Score -Descending

if (-not $topHits) { "No high-confidence hits found." }
else {
    $topHits | Select-Object Score, Reasons,
        @{N='SourceProcess'; E={Split-Path $_.SourceImage -Leaf}},
        @{N='TargetProcess'; E={Split-Path $_.TargetImage -Leaf}},
        SourceUser, TargetUser, GrantedAccess, TimeCreated |
        Format-Table -AutoSize

    "" ; "--- Highest Scoring Probable Attacker ---"
    $top = $topHits | Select-Object -First 1
    "Process  : $($top.SourceImage)"
    "User     : $($top.SourceUser)"
    "Target   : $($top.TargetImage)"
    "Access   : $($top.GrantedAccess)"
    "Score    : $($top.Score)"
    "Reasons  : $($top.Reasons)"
}
