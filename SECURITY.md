# Security Policy

## Intended Use

Latch is designed for **authorized security assessments only**. This tool should only be used:

- On systems you own
- On systems where you have explicit written permission to test
- In authorized penetration testing engagements
- In CTF (Capture The Flag) competitions
- In isolated lab environments for educational purposes

## Reporting Security Issues

If you discover a security vulnerability in Latch itself (not in the tools it downloads), please report it responsibly:

1. **Do not** create a public GitHub issue for security vulnerabilities
2. Contact the maintainers privately
3. Provide detailed information about the vulnerability
4. Allow reasonable time for a fix before public disclosure

## Tool Security Considerations

### On the Attack Host (Kali)

- `serve-tools.sh` downloads tools from GitHub - verify sources before use
- The HTTP server has no authentication - use only on trusted networks
- Tools are served from `/tmp/tools` by default - cleared on reboot

### On the Target (Windows)

- `Latch.ps1` downloads to `$env:TEMP\lt` by default - cleaned up with `-Cleanup`
- Enumeration output may contain sensitive information - handle securely
- The script is designed to evade basic AV but is not guaranteed to be undetected

## Dependencies and Supply Chain

This project downloads pre-compiled binaries from:

- [PEASS-ng](https://github.com/peass-ng/PEASS-ng) - WinPEAS, LinPEAS
- [Flangvik/SharpCollection](https://github.com/Flangvik/SharpCollection) - GhostPack tools
- [Sysinternals](https://docs.microsoft.com/sysinternals/) - Microsoft tools
- Various individual tool repositories

**Always verify tool integrity** before use in sensitive environments. Consider:

- Checking file hashes against official releases
- Building tools from source when possible
- Using `--download-only` to inspect tools before serving

## Legal Disclaimer

Unauthorized access to computer systems is illegal. Users are solely responsible for:

- Obtaining proper authorization before testing
- Complying with all applicable laws and regulations
- Any consequences resulting from misuse of this tool

The authors provide this tool for educational and authorized testing purposes only and assume no liability for misuse.
