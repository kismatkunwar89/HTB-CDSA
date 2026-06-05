# =============================================================================
# detect-clr-injection.ps1
# Detects execute-assembly / unmanaged PowerShell injection via Sysmon ID 7.
#
# IOC: clr.dll and clrjit.dll loaded inside ANY process that has no legitimate
# reason to run .NET at that specific time, from that parent, with that command.
#
# KEY PRINCIPLE: Do NOT suppress any process by name - even legitimate signed
# Microsoft processes (spoolsv.exe, taskhostw.exe, svchost.exe) are the exact
# targets attackers choose for injection BECAUSE they are trusted.
# Detection is based on CONTEXT (parent, commandline, time, integrity level),
# not on process name alone.
#
# Usage: powershell -ExecutionPolicy Bypass -File .\detect-clr-injection.ps1
# =============================================================================

# Step 0 - EVTX path (change per engagement)
$evtx = ' C:\Logs\PowershellExec\PowershellExec.evtx'

# Step 0b - CLR DLL paths to hunt (both x64 and x86 .NET 4.x)
$clrDlls = @(
    'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll',
    'C:\Windows\Microsoft.NET\Framework\v4.0.30319\clr.dll',
    'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clrjit.dll',
    'C:\Windows\Microsoft.NET\Framework\v4.0.30319\clrjit.dll'
)

# =============================================================================
# Step 1 - Find ALL CLR DLL loads (Event ID 7) - no suppression, no exclusions
# Every process that loaded the .NET runtime is shown.
# The analyst decides what is suspicious based on context.
# =============================================================================
"=== ALL CLR DLL Loads (Sysmon ID 7) - No Exclusions ==="

$clrLoads = Get-WinEvent -Path $evtx -FilterXPath "*[System[EventID=7]]" -ErrorAction SilentlyContinue |
ForEach-Object {
    try {
        $x = [xml]$_.ToXml()
        $d = $x.Event.EventData.Data
        $img    = ($d | Where-Object { $_.Name -eq 'Image'           }).'#text'
        $dll    = ($d | Where-Object { $_.Name -eq 'ImageLoaded'     }).'#text'
        $sig    = ($d | Where-Object { $_.Name -eq 'Signed'          }).'#text'
        $sigst  = ($d | Where-Object { $_.Name -eq 'SignatureStatus' }).'#text'
        $pg     = ($d | Where-Object { $_.Name -eq 'ProcessGuid'     }).'#text'
        $hashes = ($d | Where-Object { $_.Name -eq 'Hashes'          }).'#text'

        if ($clrDlls -contains $dll) {
            [pscustomobject]@{
                TimeCreated     = $_.TimeCreated
                ProcessGuid     = $pg
                Process         = (Split-Path $img -Leaf)
                Image           = $img
                ImageLoaded     = $dll
                Signed          = $sig
                SignatureStatus = $sigst
                MD5             = ($hashes -replace '.*MD5=([^,]+).*',    '$1')
                SHA256          = ($hashes -replace '.*SHA256=([^,]+).*', '$1')
                IMPHASH         = ($hashes -replace '.*IMPHASH=([^,]+).*','$1')
            }
        }
    } catch { }
}

if (-not $clrLoads) {
    "No CLR DLL loads found in this log."
    return
}

"Total CLR loads found: $($clrLoads.Count)"
""

# Step 1b - Summary table: every process that loaded CLR, sorted by time
# Use this to spot unusual processes or unusual timing
"--- All processes that loaded CLR (chronological) ---"
$clrLoads |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Process, ImageLoaded, SignatureStatus, MD5 |
    Format-Table -AutoSize

# =============================================================================
# Step 2 - Unique processes that loaded CLR
# Quickly see which distinct processes touched the .NET runtime.
# Any non-.NET process here warrants investigation.
# =============================================================================
"" ; "=== Unique Processes That Loaded CLR ==="
$clrLoads |
    Select-Object Process, Image -Unique |
    Sort-Object Process |
    Format-Table -AutoSize

# =============================================================================
# Step 3 - Build ProcessGuid list for all CLR-loading processes
# Used to pivot to Event ID 1 for full creation context.
# =============================================================================
$targets = $clrLoads.ProcessGuid | Where-Object { $_ } | Select-Object -Unique
"=== ProcessGuids to Investigate ==="
$targets

# =============================================================================
# Step 4 - Pivot to Event ID 1 for every CLR-loading process
# This is where you determine legitimacy:
#   - What spawned this process? (ParentImage)
#   - What arguments did it run with? (CommandLine)
#   - Who ran it? (User, IntegrityLevel)
#   - When relative to the CLR load? (TimeCreated)
# A process spawned by powershell.exe right before it loaded CLR = injection.
# A process spawned by services.exe at boot that loads CLR = likely legitimate.
# =============================================================================
"" ; "=== Full Context for Every CLR-Loading Process (Sysmon ID 1) ==="
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
            }
        }
    } catch { }
}

if (-not $procHits) { "No process creation events found for these ProcessGuids." }
else {
    foreach ($p in ($procHits | Sort-Object TimeCreated)) {
        "--- Process: $($p.Image) ---"
        $p | Format-List
        "    CLR DLLs loaded:"
        $clrLoads |
            Where-Object { $_.ProcessGuid -eq $p.ProcessGuid } |
            Select-Object TimeCreated, ImageLoaded, MD5 |
            Format-Table -AutoSize
    }
}

# =============================================================================
# Step 5 - Flag processes where ParentImage is a known injection launcher
# Processes spawned by powershell.exe, cmd.exe, wscript.exe, mshta.exe etc.
# that then loaded CLR are highly suspicious - this is the PSInject pattern.
# Not a suppression - just a high-confidence highlight layer on top of Step 4.
# =============================================================================
"" ; "=== High Confidence: CLR Loaded in Process Spawned by Script Host ==="
$scriptHosts = @(
    'powershell.exe', 'powershell_ise.exe', 'pwsh.exe',
    'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe',
    'rundll32.exe', 'regsvr32.exe', 'msbuild.exe'
)

$highConfidence = $procHits | Where-Object {
    $parentLeaf = Split-Path $_.ParentImage -Leaf
    $scriptHosts -contains $parentLeaf
}

if (-not $highConfidence) { "None found." }
else {
    foreach ($h in ($highConfidence | Sort-Object TimeCreated)) {
        "*** SUSPICIOUS: $($h.Image) spawned by $($h.ParentImage) ***"
        $h | Format-List
        $clrLoads |
            Where-Object { $_.ProcessGuid -eq $h.ProcessGuid } |
            Select-Object TimeCreated, ImageLoaded, MD5 |
            Format-Table -AutoSize
    }
}

# =============================================================================
# Step 6 - Timeline: correlate CLR load time vs process spawn time
# Injection happens AFTER the process is already running.
# A large gap between process creation and CLR load = runtime injection.
# A small gap (seconds) = process spawned specifically to run .NET = normal.
# =============================================================================
"" ; "=== Timeline: Process Spawn Time vs CLR Load Time ==="
if (-not $procHits) { "No process creation data to correlate." }
else {
    foreach ($p in ($procHits | Sort-Object TimeCreated)) {
        $firstClr = $clrLoads |
            Where-Object { $_.ProcessGuid -eq $p.ProcessGuid } |
            Sort-Object TimeCreated |
            Select-Object -First 1

        if ($firstClr) {
            $gap = ($firstClr.TimeCreated - $p.TimeCreated).TotalSeconds
            $flag = if ($gap -gt 30) { " *** LARGE GAP - possible injection ***" } else { "" }
            "{0,-30} spawned: {1}  |  CLR loaded: {2}  |  gap: {3}s{4}" -f `
                (Split-Path $p.Image -Leaf), $p.TimeCreated, $firstClr.TimeCreated, [math]::Round($gap,1), $flag
        }
    }
}
