# =============================================================================
# generate_msobjs_lookup.ps1 — Generate msobjs.dll message code lookup file
#
# Run this on a Windows Domain Controller or Server to extract all resolvable
# %% placeholder codes from msobjs.dll. The output JSON file is used by
# evtx_pipeline.sh to replace %% codes in EventData fields with human-readable
# descriptions.
#
# Usage:
#   .\generate_msobjs_lookup.ps1
#
# Output:
#   msobjs_lookup.json — array of { Code, Description }
#
# Example output entry:
#   { "Code": "%%1538", "Description": "READ_CONTROL" }
#
# Replacement in pipeline (Option B — code kept, description appended):
#   "%%1538" becomes "%%1538 (READ_CONTROL)"
#
# Recommended: Run on a Domain Controller or fully patched Windows Server
#   for the widest message table coverage.
# =============================================================================

$dll = "$env:SystemRoot\system32\msobjs.dll"

Add-Type -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern int FormatMessage(
    uint dwFlags, IntPtr lpSource, uint dwMessageId,
    uint dwLanguageId, System.Text.StringBuilder lpBuffer,
    uint nSize, IntPtr Arguments);
'@ -Name "WinAPIMsg" -Namespace "NativeMsg"

$hModule = [NativeMsg.WinAPIMsg]::LoadLibraryEx($dll, [IntPtr]::Zero, 0x2)
$sb = New-Object System.Text.StringBuilder 1024
$flags = 0x00000800 -bor 0x00000200

# Junk patterns — exclude placeholder/undefined entries with no analytical value
$junkPattern = "Unknown specific access \(bit|Undefined UserAccountControl Bit|Undefined Access \(no effect\) Bit|Device Access Bit|Unused message ID|^Not used$"

$results = @()

# Scan all ranges where %% codes appear in Windows Security logs
foreach ($id in (1500..2200 + 4096..4500)) {
    $sb.Clear() | Out-Null
    $len = [NativeMsg.WinAPIMsg]::FormatMessage($flags, $hModule, $id, 0, $sb, 1024, [IntPtr]::Zero)
    if ($len -gt 0) {
        $desc = $sb.ToString().Trim()
        if ($desc -notmatch $junkPattern) {
            $results += [PSCustomObject]@{
                Code        = "%%$id"
                Description = $desc
            }
        }
    }
}

$results | ConvertTo-Json -Depth 2 | Out-File ".\msobjs_lookup.json" -Encoding utf8

Write-Host "Exported $($results.Count) entries to msobjs_lookup.json"
