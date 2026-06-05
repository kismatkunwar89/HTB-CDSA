# =============================================================================
# Invoke-EvtxRecon.ps1
# First-pass recon for any Sysmon or Windows .evtx before deep hunting.
#
# Mirrors the step-by-step workflow from CDSA Module 3 Skill Assessment:
#   1. Point at the file (not the folder)
#   2. Inspect one event's XML fields
#   3. Enumerate Event IDs and counts
#   4. Optionally dump one Event ID as parsed objects
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\Invoke-EvtxRecon.ps1
#   powershell -ExecutionPolicy Bypass -File .\Invoke-EvtxRecon.ps1 -EvtxPath C:\Logs\Dump\LsassDump.evtx -EventId 10
# =============================================================================

param(
    [string]$EvtxPath = 'C:\Logs\DLLHijack\DLLHijack.evtx',
    [int]$EventId = 0,
    [int]$MaxSample = 5
)

function Write-Section([string]$Title) {
    ""
    "=== $Title ==="
}

if (-not (Test-Path -LiteralPath $EvtxPath)) {
    Write-Error "EVTX not found: $EvtxPath`nPoint to the .evtx file, not the parent folder."
    exit 1
}

Write-Section "EVTX Path"
$EvtxPath

Write-Section "Sample Event XML Fields"
$sample = Get-WinEvent -Path $EvtxPath -MaxEvents 1 -ErrorAction SilentlyContinue
if (-not $sample) {
    "No events returned from this file."
    exit 0
}

([xml]$sample.ToXml()).Event.EventData.Data |
    Select-Object Name, '#text' |
    Format-Table -AutoSize

Write-Section "Event ID Counts"
$idCounts = Get-WinEvent -Path $EvtxPath -ErrorAction SilentlyContinue |
    Group-Object -Property Id -NoElement |
    Sort-Object Count -Descending

$idCounts | Format-Table Name, Count -AutoSize

if ($EventId -gt 0) {
    Write-Section "Parsed Events for Event ID $EventId (max $MaxSample)"
    Get-WinEvent -Path $EvtxPath -FilterXPath "*[System[EventID=$EventId]]" -ErrorAction SilentlyContinue |
        Select-Object -First $MaxSample |
        ForEach-Object {
            $d = ([xml]$_.ToXml()).Event.EventData.Data
            $row = [ordered]@{ TimeCreated = $_.TimeCreated; EventID = $_.Id }
            foreach ($field in $d) {
                if ($field.Name) { $row[$field.Name] = $field.'#text' }
            }
            [pscustomobject]$row
        } | Format-List
}
