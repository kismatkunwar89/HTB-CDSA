# Step 0 — EVTX path
$evtx = 'C:\Users\Administrator\Desktop\Dllinject.evtx'

# Step 3 — Suspicious DLL loads: unsigned + outside System32/SysWOW64
$hits = Get-WinEvent -Path $evtx -FilterXPath "*[System[EventID=7]]" -ErrorAction SilentlyContinue |
ForEach-Object {
    try {
        $x = [xml]$_.ToXml()
        $d = $x.Event.EventData.Data
        $img    = ($d | Where-Object { $_.Name -eq 'Image'           }).'#text'
        $dll    = ($d | Where-Object { $_.Name -eq 'ImageLoaded'     }).'#text'
        $sig    = ($d | Where-Object { $_.Name -eq 'Signed'          }).'#text'
        $pg     = ($d | Where-Object { $_.Name -eq 'ProcessGuid'     }).'#text'
        $hashes = ($d | Where-Object { $_.Name -eq 'Hashes'          }).'#text'
        $sigst  = ($d | Where-Object { $_.Name -eq 'SignatureStatus' }).'#text'
        if ($dll -and $dll -notmatch '\\Windows\\(System32|SysWOW64)\\' -and $sig -eq 'false') {
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

"=== Suspicious DLL Loads (Sysmon ID 7) ==="
if (-not $hits) { "No suspicious DLL loads found." }
else { $hits | Sort-Object TimeCreated | Format-List }

# Step 4 — Build ProcessGuid targets
$targets = $hits.ProcessGuid | Where-Object { $_ } | Select-Object -Unique
"=== Target ProcessGuids ==="
if (-not $targets) { "None found." } else { $targets }

# Step 5 — Pivot to process creation context (Sysmon Event ID 1)
"=== Matched Process Creation Events (Sysmon ID 1) ==="
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
            }
        }
    } catch { }
}
if (-not $procHits) { "No matched process creation events found." }
else {
    foreach ($p in ($procHits | Sort-Object TimeCreated)) {
        $p | Format-List
        $hits | Where-Object { $_.ProcessGuid -eq $p.ProcessGuid } | Format-List
    }
}

# Step 6 — Loader images in writable locations
"=== Loader Images in Writable Locations ==="
$writableHits = $hits | Where-Object { $_.Image -match '\\ProgramData\\|\\Users\\|\\Temp\\|\\AppData\\' }
if (-not $writableHits) { "None found." }
else { $writableHits | Sort-Object Image -Unique | Format-List }

# Step 7 — UAC bypass: mocked trusted directory (trailing space in folder name)
# Technique: attacker creates C:\Windows \System32\ (space after Windows) using VBScript/C.
# Auto-elevate executables treat this as a trusted location, bypassing UAC entirely.
# Regex '\w+ \\' catches ANY folder with a trailing space — not just C:\Windows \,
# so it covers renamed variants too. Covers both process launches (ID 1) and DLL loads (ID 7).
"=== UAC Bypass: Trailing-Space Mocked Trusted Directory ==="
$uacHits = Get-WinEvent -Path $evtx -FilterXPath "*[System[(EventID=1 or EventID=7)]]" -ErrorAction SilentlyContinue |
ForEach-Object {
    try {
        $x = [xml]$_.ToXml()
        $d = $x.Event.EventData.Data
        $img = ($d | Where-Object { $_.Name -eq 'Image'       }).'#text'
        $dll = ($d | Where-Object { $_.Name -eq 'ImageLoaded' }).'#text'

        $suspect = @($img, $dll) | Where-Object { $_ -and $_ -match '\w+ \\' }
        if ($suspect) {
            [pscustomobject]@{
                TimeCreated = $_.TimeCreated
                EventID     = $_.Id
                SuspectPath = ($suspect -join ' | ')
                Image       = $img
                ImageLoaded = $dll
            }
        }
    } catch { }
}
if (-not $uacHits) { "None found." }
else { $uacHits | Sort-Object TimeCreated | Format-List }
