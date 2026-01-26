### Manual Enumeration

#### Directory Reconnaissance
```powershell
& {
    '=== USERS ===' | Out-File tree_all.txt
    tree C:\Users /F /A | Out-File -Append tree_all.txt
    '=== PROGRAM FILES ===' | Out-File -Append tree_all.txt
    tree 'C:\Program Files' /A | Out-File -Append tree_all.txt
    tree 'C:\Program Files (x86)' /A | Out-File -Append tree_all.txt
    '=== INETPUB ===' | Out-File -Append tree_all.txt
    tree C:\inetpub /F /A 2>$null | Out-File -Append tree_all.txt
}
```

#### Quick Wins
> PowerShell history is gold - admins type passwords in commands.

```powershell
& {
    '=== AUTOLOGON ==='
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 2>$null | Select-Object DefaultUserName,DefaultPassword,AutoAdminLogon
    '=== SAVED CREDENTIALS ==='
    cmdkey /list
    '=== POWERSHELL HISTORY ==='
    Get-Content $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -ErrorAction SilentlyContinue
    '=== ALL USERS PS HISTORY ==='
    Get-Content C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -ErrorAction SilentlyContinue
} > quickwins.txt
```

#### Unattend and Sysprep Files
> Often contain plaintext or base64 encoded passwords.

```powershell
& {
    '=== UNATTEND FILES ==='
    Get-Content C:\Unattend.xml -ErrorAction SilentlyContinue
    Get-Content C:\Windows\Panther\Unattend.xml -ErrorAction SilentlyContinue
    Get-Content C:\Windows\Panther\Unattend\Unattend.xml -ErrorAction SilentlyContinue
    Get-Content C:\Windows\system32\sysprep\sysprep.xml -ErrorAction SilentlyContinue
    Get-Content C:\Windows\system32\sysprep\sysprep.inf -ErrorAction SilentlyContinue
    '=== FOUND UNATTEND FILES ==='
    Get-ChildItem -Path C:\ -Recurse -Include *unattend*.xml,*sysprep*.xml -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
} > unattend.txt
```

#### Web Config Files
```powershell
& {
    '=== WEB.CONFIG ==='
    Get-Content C:\inetpub\wwwroot\web.config -ErrorAction SilentlyContinue
    Get-Content C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config -ErrorAction SilentlyContinue
    '=== CONNECTION STRINGS ==='
    Get-ChildItem -Path C:\ -Filter *.config -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern 'connectionString' -ErrorAction SilentlyContinue
    Get-ChildItem -Path C:\inetpub -Filter *.config -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern 'connectionString' -ErrorAction SilentlyContinue
} > webconfigs.txt
```

#### Password File Search
```powershell
& {
    '=== PASSWORD IN FILES ==='
    Select-String -Path C:\Users\*.txt,C:\Users\*.ini,C:\Users\*.config,C:\Users\*.xml -Pattern 'password=' -ErrorAction SilentlyContinue
    '=== INTERESTING FILENAMES ==='
    Get-ChildItem -Path C:\ -Recurse -Include *pass*.txt,*pass*.xml,*cred*.txt,*cred*.xml -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    '=== PRIVATE KEYS ==='
    Get-ChildItem -Path C:\ -Recurse -Include *.ppk,*id_rsa*,*id_dsa*,*.pem -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    '=== KEEPASS ==='
    Get-ChildItem -Path C:\ -Recurse -Include *.kdbx -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
} > password_files.txt
```

#### Registry Credentials
```powershell
& {
    '=== PUTTY SESSIONS ==='
    reg query 'HKCU\Software\SimonTatham\PuTTY\Sessions' /s 2>$null
    '=== VNC ==='
    reg query 'HKCU\Software\ORL\WinVNC3\Password' 2>$null
    reg query 'HKCU\Software\TightVNC\Server' 2>$null
    reg query 'HKLM\SOFTWARE\RealVNC\WinVNC4' /v password 2>$null
    '=== SNMP ==='
    reg query 'HKLM\SYSTEM\CurrentControlSet\Services\SNMP' /s 2>$null
} > reg_creds.txt
```

#### Full Registry Password Search [optional]
> Slow - run in background.

```powershell
Start-Job { reg query HKLM /f password /t REG_SZ /s > reg_hklm_passwords.txt 2>&1 }
Start-Job { reg query HKCU /f password /t REG_SZ /s > reg_hkcu_passwords.txt 2>&1 }
```
