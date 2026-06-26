# Packetra Windows Agent Guide

## 1. What the Agent MSI should do

When you run `PacketraAgent.msi` on the Windows client machine, the goal is that the client prepares itself in one installation flow so the Packetra server only needs to connect over SSH later.

The MSI now performs these steps:

1. Copies `RemoteCaptureAgent.exe` to the Packetra agent install directory.
2. Checks whether OpenSSH Client and OpenSSH Server are already installed.
3. If OpenSSH components are missing, installs them.
4. Ensures `C:\Windows\System32\OpenSSH` is available in the machine `PATH`.
5. Ensures the `sshd` service is enabled and started.
6. Checks whether Npcap is already installed.
7. If Npcap is missing, downloads or reuses the Npcap installer and runs it.
8. Checks whether the `PacketraAgent` Windows service already exists.
9. If the service does not exist, installs it and starts it.
10. If the service already exists, updates it and starts it if needed.

If you run the same MSI again later, Windows Installer should offer the normal maintenance flow such as `Repair` or `Remove`.

## 2. How to check whether the agent installed correctly

Open PowerShell on the Windows client and run:

```powershell
Get-Service PacketraAgent -ErrorAction SilentlyContinue
Get-Service sshd -ErrorAction SilentlyContinue
Get-Service npcap -ErrorAction SilentlyContinue
where.exe RemoteCaptureAgent.exe
where.exe ssh.exe
```

Expected results:

- `PacketraAgent` should exist.
- `PacketraAgent` should normally be `Running`.
- `sshd` should exist and normally be `Running`.
- `npcap` should exist.
- `RemoteCaptureAgent.exe` should resolve to the Packetra agent install directory.
- `ssh.exe` should resolve inside `C:\Windows\System32\OpenSSH` or another valid OpenSSH path.

If the MSI fails during prerequisite bootstrap, also check:

```powershell
Get-Content "$env:TEMP\PacketraAgent-bootstrap.log" -ErrorAction SilentlyContinue
```

That log contains the detailed reason from the bootstrap phase.

## 3. How to understand the current broken state

If you see a result like this:

```powershell
Get-Service PacketraAgent -ErrorAction SilentlyContinue
where.exe RemoteCaptureAgent.exe
C:\Users\<user>\AppData\Local\Programs\PacketraAgent\RemoteCaptureAgent.exe
```

that means:

- the agent executable exists
- but the Windows service was not created
- and the machine is likely still using an older Packetra agent install layout

In that state, the server can fail to load remote interfaces because SSH works, but the server-side remote command cannot find or validate the expected agent installation path or service state cleanly.

## 4. Recommended recovery steps for a broken or old client install

1. Download the latest `packetra-remote-agent.zip` from Packetra again.
2. Extract the ZIP.
3. Run the latest `PacketraAgent.msi`.
4. If Windows Installer shows maintenance options, choose `Repair`.
5. After it finishes, run the PowerShell validation block again.

Validation block:

```powershell
Get-Service PacketraAgent -ErrorAction SilentlyContinue
Get-Service sshd -ErrorAction SilentlyContinue
Get-Service npcap -ErrorAction SilentlyContinue
where.exe RemoteCaptureAgent.exe
```

## 5. Detailed service checks

To inspect the exact service registration:

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\PacketraAgent' -ErrorAction SilentlyContinue
sc.exe qc PacketraAgent
sc.exe query PacketraAgent
```

Useful things to verify:

- `ImagePath` points to `RemoteCaptureAgent.exe`
- startup type is automatic
- current state is `RUNNING`

## 6. Detailed OpenSSH checks

```powershell
Get-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Get-Service sshd -ErrorAction SilentlyContinue
where.exe ssh.exe
```

If `State` is `Installed` and `sshd` is running, the SSH part is ready for Packetra server connections.

## 7. Detailed Npcap checks

```powershell
Get-Service npcap -ErrorAction SilentlyContinue
Get-Service npcapwatchdog -ErrorAction SilentlyContinue
```

If one of these services exists, Npcap is typically installed.

## 8. How to remove the Windows agent completely

### Step 1. Check current state first

```powershell
$svc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\PacketraAgent' -ErrorAction SilentlyContinue
$img = $svc.ImagePath
if ($img) { Write-Host "[+] Service ImagePath: $img" -ForegroundColor Green }
Get-Service PacketraAgent -ErrorAction SilentlyContinue
where.exe RemoteCaptureAgent.exe
```

### Step 2. Use the MSI remove flow first

If you still have the same `PacketraAgent.msi`, run it again and choose `Remove`.

This is the preferred path because it lets Windows Installer remove the registered product cleanly.

### Step 3. Manual cleanup if the service or files remain

Run PowerShell as Administrator:

```powershell
sc.exe stop PacketraAgent
sc.exe delete PacketraAgent
taskkill /f /im RemoteCaptureAgent.exe
```

Then delete the remaining install folder if it still exists.

Example:

```powershell
Remove-Item -Recurse -Force "C:\Program Files\PacketraAgent"
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\Programs\PacketraAgent"
```

Only delete the path that actually exists on that client.

### Step 4. Optional prerequisite cleanup

Remove OpenSSH only if you are sure nothing else on the client needs it:

```powershell
Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Remove-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```

Npcap is usually best removed from Windows Apps & Features or the official Npcap uninstaller.

## 9. Final remove verification

```powershell
Get-Service PacketraAgent -ErrorAction SilentlyContinue
where.exe RemoteCaptureAgent.exe
```

Expected result:

- `PacketraAgent` no longer appears
- `RemoteCaptureAgent.exe` no longer resolves from `where.exe`
