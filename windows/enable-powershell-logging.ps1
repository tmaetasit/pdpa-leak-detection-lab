# Day 5: run once in an elevated PowerShell on the Windows lab VM.
# Turns on PowerShell Script Block Logging (Event 4104) and Module Logging,
# and makes the Wazuh agent read Microsoft-Windows-PowerShell/Operational.
# New PowerShell sessions pick the policy up; already open ones do not.
$sb = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $sb -Force | Out-Null
Set-ItemProperty $sb EnableScriptBlockLogging 1
$ml = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
New-Item -Path "$ml\ModuleNames" -Force | Out-Null
Set-ItemProperty $ml EnableModuleLogging 1
Set-ItemProperty "$ml\ModuleNames" '*' '*'

$conf = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
Copy-Item $conf "$conf.bak-day5" -Force
if (-not (Select-String -Path $conf -Pattern 'PowerShell/Operational' -Quiet)) {
  Add-Content $conf "`n<ossec_config>`n  <localfile>`n    <location>Microsoft-Windows-PowerShell/Operational</location>`n    <log_format>eventchannel</log_format>`n  </localfile>`n</ossec_config>"
}
# Restart-Service can time out while the agent stops: wait for Stopped.
Stop-Service WazuhSvc
while ((Get-Service WazuhSvc).Status -ne 'Stopped') { Start-Sleep 2 }
Start-Service WazuhSvc
Get-Service WazuhSvc | Format-Table Name, Status
