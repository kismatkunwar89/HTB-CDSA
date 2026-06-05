# =============================================================================
# detect-strange-ppid.ps1
# Hunts PPID spoofing / impossible parent-child pairs via Sysmon Event ID 1,
# then correlates Event ID 8 (CreateRemoteThread) injection into the spoofed parent.
#
# IOC: trusted system process spawning cmd/powershell, often after remote thread
# injection with StartModule/StartFunction empty (shellcode).
#
# Usage: powershell -ExecutionPolicy Bypass -File .\2-detect.ps1
# =============================================================================

$evtx = 'C:\Logs\StrangePPID\StrangePPID.evtx'

$neverSpawnShell = @(
    'WerFault.exe', 'svchost.exe', 'spoolsv.exe', 'lsass.exe',
    'winlogon.exe', 'services.exe', 'smss.exe', 'csrss.exe',
    'taskhost.exe', 'taskhostw.exe'
)

$shellChildren = @('cmd.exe', 'powershell.exe', 'powershell_ise.exe', 'pwsh.exe', 'whoami.exe')

# =============================================================================
# Step 1 - Event ID inventory
# =============================================================================
"=== Event ID Counts ==="
Get-WinEvent -Path $evtx -ErrorAction SilentlyContinue |
    Group-Object -Property Id -NoElement |
    Sort-Object Count -Descending |
    Format-Table Name, Count -AutoSize

# =============================================================================
# Step 2 - Dump all process creations (small logs = full dump)
# =============================================================================
"" ; "=== All Process Creations (Sysmon ID 1) ==="
$procCreates = Get-WinEvent -FilterHashtable @{ Path = $evtx; Id = 1 } -ErrorAction SilentlyContinue |
ForEach-Object {
    $d = ([xml]$_.ToXml()).Event.EventData.Data
    [pscustomobject]@{
        TimeCreated       = $_.TimeCreated
        ProcessGuid       = ($d | Where-Object { $_.Name -eq 'ProcessGuid'       }).'#text'
        Image             = ($d | Where-Object { $_.Name -eq 'Image'             }).'#text'
        CommandLine       = ($d | Where-Object { $_.Name -eq 'CommandLine'       }).'#text'
        ParentImage       = ($d | Where-Object { $_.Name -eq 'ParentImage'       }).'#text'
        ParentCommandLine = ($d | Where-Object { $_.Name -eq 'ParentCommandLine' }).'#text'
        User              = ($d | Where-Object { $_.Name -eq 'User'              }).'#text'
        IntegrityLevel    = ($d | Where-Object { $_.Name -eq 'IntegrityLevel'    }).'#text'
    }
}

if (-not $procCreates) { "No process creation events found."; return }
$procCreates | Sort-Object TimeCreated | Format-List

# =============================================================================
# Step 3 - Flag impossible parent -> child relationships
# =============================================================================
"" ; "=== Impossible Parent-Child Pairs ==="
$suspicious = $procCreates | Where-Object {
    $parentLeaf = Split-Path $_.ParentImage -Leaf
    $childLeaf  = Split-Path $_.Image -Leaf
    ($neverSpawnShell -contains $parentLeaf) -and ($shellChildren -contains $childLeaf)
}

if (-not $suspicious) { "None found." }
else {
    foreach ($hit in ($suspicious | Sort-Object TimeCreated)) {
        "*** SUSPICIOUS: $($hit.ParentImage) -> $($hit.Image) ***"
        $hit | Format-List
    }
}

# =============================================================================
# Step 4 - CreateRemoteThread (Event ID 8) for injection context
# =============================================================================
"" ; "=== CreateRemoteThread Events (Sysmon ID 8) ==="
$threads = Get-WinEvent -FilterHashtable @{ Path = $evtx; Id = 8 } -ErrorAction SilentlyContinue |
ForEach-Object {
    $d = ([xml]$_.ToXml()).Event.EventData.Data
    [pscustomobject]@{
        TimeCreated   = $_.TimeCreated
        SourceImage   = ($d | Where-Object { $_.Name -eq 'SourceImage'   }).'#text'
        TargetImage   = ($d | Where-Object { $_.Name -eq 'TargetImage'   }).'#text'
        StartAddress  = ($d | Where-Object { $_.Name -eq 'StartAddress'  }).'#text'
        StartModule   = ($d | Where-Object { $_.Name -eq 'StartModule'   }).'#text'
        StartFunction = ($d | Where-Object { $_.Name -eq 'StartFunction' }).'#text'
    }
}

if (-not $threads) { "No CreateRemoteThread events found." }
else {
    $threads | Format-List
    $shellcode = $threads | Where-Object { -not $_.StartModule -or $_.StartModule -eq '-' }
    if ($shellcode) {
        "" ; "=== Shellcode Indicator (empty StartModule/StartFunction) ==="
        $shellcode | Format-List
    }
}

# =============================================================================
# Step 5 - Summary
# =============================================================================
"" ; "=== FINAL SUMMARY ==="
"Process creates : $(@($procCreates).Count)"
"Suspicious pairs: $(@($suspicious).Count)"
"Remote threads  : $(@($threads).Count)"
