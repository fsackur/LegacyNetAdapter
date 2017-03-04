Import-Module $PSScriptRoot\..\LegacyNetAdapter.psd1 -Force
Write-host "Pester testing on something written for Powershell 2.0? ...ha ha, no."

$RaxAdapter = Get-WmiAdapter -Primary | Add-AdapterMagic
$null -ne $RaxAdapter.DnsServers
$null -ne $RaxAdapter.DefaultGateway
$null -ne $RaxAdapter.IPAddresses
$IP = [system.net.ipaddress]"1.1.1.1" | Add-IpAddressMagic -SubnetMask 255.255.255.128
$IP.IsInSameSubnet("1.1.1.19") -is [bool]
$IP.IsInSameSubnet("1.1.4.44") -is [bool]

