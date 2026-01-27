# Contributing to Latch

Thanks for your interest in contributing to Latch!

## Ways to Contribute

### Adding New Tools

To add a new tool to `serve-tools.sh`:

1. Find the tool's GitHub release URL or raw download link
2. Add an entry to the `TOOLS` array:

```bash
TOOLS["ToolName.exe"]="search_patterns|download_url|post_process|folder"
```

**Fields:**
- `search_patterns`: Space-separated filenames to find locally (case-insensitive)
- `download_url`: Direct download URL (GitHub releases preferred)
- `post_process`: `none`, `unzip`, `ungzip`, `unzip_find:filename`, `untar_find:filename`
- `folder`: Subdirectory name for organization

3. Add the folder to the appropriate category in the `CATEGORIES` array:

```bash
CATEGORIES["Enumeration"]="WinPEAS LinPEAS ... YourNewTool"
```

### Adding Enumeration Checks

To add a new check to `Latch.ps1`:

1. Add the check in the appropriate section (or create a new section)
2. Use `Write-Status` for output:
   - `Write-Status "Message" "INFO"` - Informational
   - `Write-Status "Message" "SUCCESS"` - Successful operation
   - `Write-Status "Message" "WARNING"` - Warning
   - `Write-Status "Message" "ERROR"` - Error
   - `Write-Status "Message" "CRITICAL"` - Critical finding

3. Output results to a file in `$OutputDir`
4. For critical findings, create an alert file (e.g., `FINDING_NAME_FOUND.txt`)

### Defender Evasion

When adding new code to `Latch.ps1`, use string concatenation for sensitive strings:

```powershell
# Bad - easily detected
$tool = "mimikatz.exe"

# Good - concatenated
$tool = "mimi" + "katz" + ".exe"
```

## Pull Request Guidelines

1. **Test your changes** - Run `serve-tools.sh --download-only` to verify tool downloads
2. **Update documentation** - Update README.md if adding new features or tools
3. **Keep commits focused** - One feature/fix per PR
4. **Follow existing patterns** - Match the code style of existing files

## Reporting Bugs

When reporting bugs, include:

- OS version (Windows/Kali version)
- PowerShell/Bash version
- Steps to reproduce
- Expected vs actual behavior
- Error messages (if any)

## Feature Requests

Feature requests are welcome! Please include:

- Use case description
- Expected behavior
- Any relevant examples or references

## Code of Conduct

- Be respectful and constructive
- This is a security tool - use responsibly
- No malicious contributions (backdoors, data exfiltration, etc.)
