# NetAdapter
Backward compatible module for configuring network adapters

# Overview
The building blocks of this module are:

 - Get-WmiAdapter and Get-WmiConfiguration. These correctly identify the "priamry" network adapter and save cut'n'paste WMI code. They return the WMI objects you would expect.
 - Add-IpAddressMagic, Add-AdapterMagic. These increase the utility of objects. THe IP one adds some members to System.Net.IpAddress so that it is subnet-aware and has methods such as IsInSameSubnet(). The Adapter one takes a WMI object and gives you a useful PSCustomObject back.

Ideally, we'd extend the IpAddress class, but that cannot be done even in PS 5.0. You would need to write C# - which is an exercise I leave to you, good buddies.

# Usage
$Adapter = Get-WmiAdapter | Add-AdapterMagic

Add-IPAddressToPrimaryAdapter -NewIP "192.168.66.66"   #Prevents a helpdesk imp from bringing the server down; returns string[] log output

$IP = [ipaddress]"10.20.0.45" | Add-IpAddressMagic -SubnetMask "255.255.248.0"
$IP.IsInSameSubnet("10.40.0.18")
