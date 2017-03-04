<#
    .AUTHOR
    Copyright Freddie Sackur 2017
    https://github.com/fsackur/LegacyNetAdapter
#>

function Get-WmiAdapter {
    <#
        .Synopsis
        Get WMI objects for network adapters

        .Description
        Returns WMI objects of class Win32_NetworkAdapter.
        
        By default, gets all network adapters that have a display name configured in ncpa.cpl - this excludes Bluetooth, Teredo etc

        The Primary switch causes only the primary adapter to be returned. This is chosen by looking at all adapters that have a
        default gateway configured and picking the default gateway with the lowest metric.

        .Inputs
        Primary - return the primary IP adapter, as chosen by examination of the routing table

        Identity - return adapter by display name (as configured in ncpa.cpl)

        IncludeUnnamed - also return adapters that have no display name configured in ncpa.cpl, e.g. Bluetooth adapters.

        .Outputs
        Array of WMI objects of class Win32_NetworkAdapter
    #>
    [CmdletBinding(DefaultParameterSetName='Default')]
    [OutputType([System.Management.ManagementObject[]])] #root\cimv2\Win32_NetworkAdapter])]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='Primary')]
        [switch]$Primary,

        [Parameter(Mandatory=$true, ParameterSetName='Identity', Position=0)]
        [string]$Identity,

        [Parameter(Mandatory=$true, ParameterSetName='IncludeUnnamed')]
        [switch]$IncludeUnnamed
    )

    switch ($PSCmdlet.ParameterSetName) {
        'Primary'
                        {
                            $DefaultRouteInterfaceIndex = Get-WmiObject Win32_IP4RouteTable -Filter "Name='0.0.0.0'" |
                                sort Metric1 | select -First 1 -ExpandProperty InterfaceIndex
                            $Filter = "InterfaceIndex='$DefaultRouteInterfaceIndex'"
                            break
                        }

        'Identity'
                        {
                            $Filter = "NetConnectionID LIKE '$Identity'"
                        }

        'IncludeUnnamed'
                        {
                            $Filter = ""
                            break
                        }

        default
                        {
                            $Filter = "NetConnectionID LIKE '%'"
                        }

    }


    $NetworkAdapters = Get-WmiObject Win32_NetworkAdapter -Filter $Filter

    return $NetworkAdapters
}

function Get-WmiAdapterConfiguration {
    <#
        .Synopsis
        Get WMI objects for network adapter configurations

        .Description
        Returns WMI objects of class Win32_NetworkAdapterConfiguration.
        
        By default, gets all network adapters that have a display name configured in ncpa.cpl - this excludes Bluetooth, Teredo etc

        The Primary switch causes only the primary adapter to be returned. This is chosen by looking at all adapters that have a
        default gateway configured and picking the default gateway with the lowest metric.

        .Inputs
        Primary - return the primary IP adapter, as chosen by examination of the routing table

        Identity - return adapter by display name (as configured in ncpa.cpl)

        IncludeUnnamed - also return adapters that have no display name configured in ncpa.cpl, e.g. Bluetooth adapters.

        WmiAdapter - return the configuration object associated with the specified network adapter WMI object.

        .Outputs
        Array of WMI objects of class Win32_NetworkAdapterConfiguration
    #>
    [CmdletBinding(DefaultParameterSetName='Default')]
    [OutputType([System.Management.ManagementObject[]])] #root\cimv2\Win32_NetworkAdapter])]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='Primary')]
        [switch]$Primary,

        [Parameter(Mandatory=$true, ParameterSetName='Identity', Position=0)]
        [string]$Identity,

        [Parameter(Mandatory=$true, ParameterSetName='GetAssociated', Position=0, ValueFromPipeline=$true)]
        [ValidateScript({$_.__CLASS -like "Win32_NetworkAdapter"})]
        [System.Management.ManagementObject[]]$WmiAdapter,

        [Parameter(Mandatory=$true, ParameterSetName='IncludeUnnamed')]
        [switch]$IncludeUnnamed
    )

    begin {
        if ($WmiAdapter) {
            $WmiAdapter | foreach {
                if ($_.__CLASS -notlike "Win32_NetworkAdapter") {
                    throw "WmiAdapter must be an instance of Win32_NetworkAdapter"
                }
            }
        }
    }

    process {

        if ($PSCmdlet.ParameterSetName -ne 'GetAssociated') {
            $WmiAdapter = Get-WmiAdapter @PSBoundParameters
        }


        $WmiAdapter | foreach {
            Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "Index='$($_.DeviceID)'"
        }
    }
}

function Add-AdapterMagic {
    <#
    .Synopsis
        Turns a WMI Win32_NetworkAdapter object into a much more useful object.
    
    .Description
        Creates a PSCustomObject with typename of Custom.WindowsAutomation.NetworkAdapter. Note that the underlying object is pscustomobject, as revealed by GetType(). This has the most commonly-used properties of the Win32_NetworkAdapter and Win32_NetworkAdapterConfiguration classes, as well as some useful transformations (IP addresses are converted into an array of Custom.WindowsAutomation.IpAddress objects, for example)

        The Win32_NetworkAdapter and Win32_NetworkAdapterConfiguration objects are also added themselves as properties - so, any method you need from the WMI object is accessible.

    .Inputs
        WmiAdapter - accepts pipeline input - the instance of Win32_NetworkAdapter that you wish to base the resulting object on.

    .Example
        Get-WmiAdapter -Primary | Add-AdapterMagic

    #>
    [CmdletBinding(ConfirmImpact='Medium')]
    [OutputType([System.Management.ManagementObject])]

    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$True)]
        [ValidateScript({$_.__CLASS -like "Win32_NetworkAdapter"})]
        [System.Management.ManagementObject]$WmiAdapter
    )

    process {

        if ($WmiAdapter.__CLASS -notlike "Win32_NetworkAdapter") {
            Write-Error "WmiAdapter must be an instance of Win32_NetworkAdapter"
            return
        }

        $PropertiesToKeep = @(
            @{Name="Name"; Expression={$_.NetConnectionID}}
            "*?Name"
            'AdapterType',
            'AdapterTypeId',
            'Caption',
            'Description',
            'GUID',
            'Index',
            'InstallDate',
            'Installed',
            'InterfaceIndex',
            'MACAddress',
            'Manufacturer',
            'NetConnectionID',
            'NetConnectionStatus',
            'NetEnabled',
            'PhysicalAdapter',
            'PNPDeviceID',
            'PowerManagementCapabilities',
            'Speed'
        )

        $CustomAdapter = $WmiAdapter | select $PropertiesToKeep

        $WmiConfiguration = Get-WmiAdapterConfiguration -WmiAdapter $WmiAdapter
        Add-Member -InputObject $CustomAdapter -MemberType ScriptProperty -Name WmiAdapter -Value {Get-WmiAdapter -Identity $this.Name}
        Add-Member -InputObject $CustomAdapter -MemberType ScriptProperty -Name WmiConfiguration -Value {Get-WmiAdapterConfiguration -Identity $this.Name}
    
        $ConfPropertiesToAdd = @(
            'DHCPLeaseExpires',
            'DHCPEnabled',
            'DHCPLeaseObtained',
            'DHCPServer',
            'DNSDomainSuffixSearchOrder',
            'DNSEnabledForWINSResolution',
            'DNSHostName',
            'DomainDNSRegistrationEnabled',
            'FullDNSRegistrationEnabled',
            'IPConnectionMetric',
            'IPEnabled',
            'IPSubnet',
            'MTU'
        )

        $ConfPropertiesToAdd | foreach {
            Add-Member -InputObject $CustomAdapter -MemberType NoteProperty -Name $_ -Value $($WmiConfiguration.$_)
        }

        Add-Member -InputObject $CustomAdapter -MemberType NoteProperty -Name DnsServers -Value $(($WmiConfiguration).DNSServerSearchOrder | %{[ipaddress]$_})
        Add-Member -InputObject $CustomAdapter -MemberType NoteProperty -Name DefaultGateway -Value $($WmiConfiguration.DefaultIPGateway | %{[ipaddress]$_})
        Add-Member -InputObject $CustomAdapter -MemberType NoteProperty -Name IPAddresses -Value $(
            $IPAddresses = [ipaddress[]]@()
            for ($i=0; $i -lt $WmiConfiguration.IPAddress.Count; $i++) {
                $IPAddress = [ipaddress]$WmiConfiguration.IPAddress[$i]
                if ($IPAddress.AddressFamily -like "InterNetworkV6") {continue}  #Skip IPv6
                $IPAddress = $IPAddress | Add-IpAddressMagic -SubnetMask $WmiConfiguration.IPSubnet[$i]
                $IPAddresses += $IPAddress
            }
            $IPAddresses | sort Binary
        )



        Add-Member -InputObject $CustomAdapter -MemberType NoteProperty -Name IPv6Addresses -Value $(
            $IPv6Addresses = [ipaddress[]]@()
            for ($i=0; $i -lt $WmiConfigurationObject.IPAddress.Count; $i++) {
                $IPAddress = [ipaddress]$WmiConfigurationObject.IPAddress[$i]
                if ($IPAddress.AddressFamily -like "InterNetwork") {continue}  #Skip IPv4
                $IPv6Addresses += $IPAddress
            }
        )

    
        $DisplayProperties = @('Name', 'IPAddresses', 'DefaultGateway', 'DnsServers')
        $SortProperties = @('NetEnabled', 'IPEnabled', 'Name', 'InterfaceIndex', 'Index')

        $CustomAdapter | Add-DefaultMembers -DisplayProperties $DisplayProperties -SortProperties $SortProperties -TypeName "Custom.WindowsAutomation.NetworkAdapter"

        return $CustomAdapter
    }
}

function Add-IpAddressMagic {
    <#
    .Synopsis
        Turns a System.Net.IpAddress object into a more useful object.
    
    .Description
        Creates a PSCustomObject with typename of Custom.WindowsAutomation.IpAddress. This has additional properties that encapsulate the subnet that the IP address is located in, which makes it easier to perform netowrking operations.

        This also makes it possible to sort the resulting objects.

    .Inputs
        Ip - the ip address in question. IPv6 is not currently supported.

        SubnetMask - specifies the subnet mask of the IP address, as a System.Net.IpAddress object

        Cidr - specifies the subnet mask of the IP address as the number of bits in the network section

    .Example
        #returns an ip address with subnet mask
        "10.0.0.2" | Add-IpAddressMagic -Cidr 27

        #returns "10.0.0.0/27"
        ("10.0.0.2" | Add-IpAddressMagic -SubnetMask "255.255.255.224").GetNetworkPrefix()

        #returns true
        $Ip1 = "10.0.0.2" | Add-IpAddressMagic -Cidr 27
        $Ip2 = "10.0.0.8" | Add-IpAddressMagic -Cidr 27
        $Ip1.IsInSameSubnet($Ip2)

    #>
    [CmdletBinding(DefaultParameterSetName='Cidr')]
    [OutputType([ipaddress])]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline = $true)]
        [ipaddress]$Ip,
        [Parameter(Mandatory=$false, Position=1, ParameterSetName='SubnetMask')]
        [ValidateScript({ConvertTo-Binary -IpAddress $_ | foreach {($_ -match '^1*0*$') -and ($_.Length -eq 32)}})]
        [ipaddress]$SubnetMask,
        [Parameter(Mandatory=$false, Position=1, ParameterSetName='Cidr')]
        [ValidateRange(0,32)]
        [uint16]$Cidr
    )

    if ($IPAddress.AddressFamily -like "InterNetworkV6") {
        throw "IPv6 support is not implemented yet"
    }

    $Ip.PSTypeNames.Insert(0, 'Custom.WindowsAutomation.IpAddress')

    if ($Cidr) {$SubnetMask = ConvertFrom-Binary -BinaryIPAddress ("1" * $Cidr).PadRight(32, '0')}

    Add-Member -InputObject $Ip -MemberType NoteProperty -Name SubnetMask -Value $SubnetMask
    Add-Member -InputObject $Ip -MemberType ScriptMethod -Name GetNetworkPrefix -Value {Get-NetworkPrefix -IpAddress $this -SubnetMask $this.SubnetMask}


    switch ($PSCmdlet.ParameterSetName) {
        'SubnetMask' {
            if ($Ip.AddressFamily -ne $SubnetMask.AddressFamily) {throw (New-Object System.FormatException ("IP and subnet mask must be of same family"))}
            Add-Member -InputObject $Ip -MemberType ScriptProperty -Name Cidr -Value {(ConvertTo-Binary -IpAddress $this.SubnetMask).IndexOf('0')}
        }
        'Cidr' {
            Add-Member -InputObject $Ip -MemberType NoteProperty -Name Cidr -Value $Cidr
        }
    }

    
    Add-Member -InputObject $Ip -MemberType ScriptMethod -Name IsInSameSubnet -Value {
        param([ipaddress]$Ip)
        if (-not $this.GetNetworkPrefix()) {
            throw "You cannot call this method on an IpAddress that did not have a subnet or cidr configured at creation time using Add-AdapterMagic"
        }
        return Test-IsInSameSubnet -NetworkPrefix $this.GetNetworkPrefix() -IPAddress $Ip
    }

    Add-Member -InputObject $Ip -MemberType ScriptProperty -Name Binary -Value {
        return ConvertTo-Binary -IpAddress $this
    }

    Add-Member -InputObject $Ip -MemberType ScriptMethod -Name CompareTo -Value {
        [Outputtype([Int32])]
        param([ipaddress]$Ip)
        $BytesThis = $this -split '\.'
        $BytesThat = $Ip -split '\.'
        for ($i=0; $i -lt $BytesThis.Count; $i++) {
            $c = ([int]$BytesThis[$i]).CompareTo(([int]$BytesThat[$i]))
            if ($c) {return $c}
        }
        return 0
    }

    return $Ip
}

function ConvertTo-Binary {
    <#
        .Synopsis
        Converts an IP address into its string representation in binary format

        .Description
        Converts an address to binary format, namely, a string with length 32 (IPv4) or 128 (IPv6) composed of 1s and 0s
        
        .Example
        ConvertTo-Binary -IPAddress 192.168.100.24

        .Output
        String: representation of the address in binary

        .Notes
        Non-destructive
    #>
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, ValueFromRemainingArguments=$true, Position=0)]
        [ipaddress]$IpAddress
    )
    
    #String in 1s and 0s
    $BinaryBytes = $IPAddress | %{$_.GetAddressBytes() | %{[Convert]::ToString($_, 2).PadLeft(8, '0')}}
    
    #32 character string of 1s and 0s (or 128 if we go with IPv6)
    return $BinaryBytes -join ''
    
}

function ConvertFrom-Binary {
    <#
        .Synopsis
        Converts a string representation of an address in binary back to an ip address

        .Description
        Converts an address to binary format, namely, a string with length 32 (IPv4) or 128 (IPv6) composed of 1s and 0s
        
        .Example
        ConvertTo-Binary -IPAddress 192.168.100.24

        .Outputs
        String: representation of the address in binary

        .Notes
        Non-destructive
    #>
    param(
        [ValidateScript({($_.Length -eq 32 -or $_.Length -eq 128) -and $_ -match "^(0|1)*$"})]
        [string]$BinaryIPAddress
    )

    if ($BinaryIPAddress.Length -eq 128) {throw "IPv6 support is not implemented yet"}

    $Bin = $BinaryIPAddress  #required due to validation  
    $Bytes = @()
    while ($Bin.Length -ge 8) {
        $Byte = [convert]::ToInt32($Bin.Substring(0,8),2)
        $Bytes += $Byte
        $Bin = $Bin.Substring(8)

    }

    return $Bytes -join "."
}

function Get-NetworkPrefix {
    <#
        .Synopsis
        Returns a network address in CIDR format
       
        .Example
        #Returns 192.168.100.24/16
        Get-NetworkPrefix -IPAddress 192.168.100.24 -SubnetMask 255.255.0.0

        .Outputs
        String: representation of the network address in CIDR format
    #>
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [ipaddress]$IpAddress,

        [Parameter(Mandatory=$true, Position=1)]
        [ipaddress]$SubnetMask
    )

    $NetworkAddress = ([ipaddress]($IpAddress.Address -band $SubnetMask.Address)).ToString()

    $CidrLength = (ConvertTo-Binary -IpAddress $SubnetMask).IndexOf('0')

    return "$NetworkAddress/$CidrLength"
}

function Test-IsInSameSubnet {
    <#
        .Synopsis
        Returns whether or not two or more IP Addresses are in the same subnet

        .Description
        
        .Example
        #Returns false:
        Test-IsInSameSubnet -IPAddresses 192.168.100.24, 192.168.102.65 -PrefixLength 24
        
        #Returns true:
        Test-IsInSameSubnet -IPAddress 192.168.100.24 -NetworkPrefix 192.168.100.65/24

        .Outputs
        Boolean: Whether or not the specified IP addresses are in the same subnet

        .Notes
        Non-destructive
    
    #>
    [CmdletBinding(ConfirmImpact='Low')]
    [OutputType([bool])]

    param(
        [Parameter(Mandatory=$true, ParameterSetName='IPArray', Position=0)]
        [ValidateCount(2,100)]
        [ipaddress[]]$IPAddresses,
        [Parameter(Mandatory=$true, ParameterSetName='IPArray', Position=1)]
        [ValidateRange(0,32)]
        [int]$PrefixLength,

        [Parameter(Mandatory=$true, ParameterSetName='IPAndPrefix', Position=0)]
        [ipaddress]$IPAddress,
        [Parameter(Mandatory=$true, ParameterSetName='IPAndPrefix', Position=1)]
        [ValidateScript({$_ -match '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'})]
        [string]$NetworkPrefix             #CIDR format, e.g. 1.2.3.4/16
    )

    if ($PSCmdlet.ParameterSetName -like "IPAndPrefix") {
        $IPAddresses = @($IPAddress, [ipaddress]($NetworkPrefix -split '/')[0])
        $PrefixLength = ($NetworkPrefix -split '/')[1]
    }

    $BinaryIPs = $IPAddresses | %{ConvertTo-Binary -IPAddress $_}
    $BinaryPrefixes = $BinaryIPs | %{$_.Substring(0, $PrefixLength)}
    return !(($BinaryPrefixes | sort -Unique).Count -gt 1)

}


function Add-IPAddressToPrimaryAdapter {
    <#
    .Synopsis
        Creates and configures an IP address on the primary network adapter
    
    .Description
        The primary network adapter is defined as the adapter that has the default gateway that has the highest metric.

        This function accepts an IP address and subnet mask, as a [System.Net.IPAddress] that has had extra properties added. To generate this input argument, pass an IP address object to Add-IpAddressMagic and specify either the SubnetMask or Cidr parameter.
    
        This function will not make changes if any of the following checks fail:
            DHCP is disabled
            The new IP address is already present on the adapter
            Multiple default gateways are configured on the adapter
            The new IP address, the default gateway and all the current IP addresses on the adapter are not all in the same subnet
            The new IP address is numerically between existing IP addresses on the adapter
            The new IP address is numerically closer to the default gateway than any existing IP addresses on the adapter
        Part of this is due to the -SkipAsSource behaviour.
    #>

    [CmdletBinding(ConfirmImpact='Medium')]
    [OutputType([void])]

    param(
        [Parameter(Mandatory=$true, Position=0)]
        [ipaddress]$NewIP,
        [switch]$Force
    )

    $Log = @()

    $Adapter = Get-WmiAdapter -Primary | Add-AdapterMagic
    

    $Log += "Adapter $($Adapter.Name)"

    if ((-not $Force) -and ((Read-Host "Add $NewIP to adapter $($Adapter.Name) (Y/N)") -notlike "y")) {
        $Log += "User selected quit"
        return $Log
    }

    if ($Adapter.DHCPEnabled) {
        $Log += "DHCP is enabled; quitting"
        return $Log
    }

    if (($Adapter.IPAddresses | select -ExpandProperty IPAddressToString) -contains $NewIP.IPAddressToString) {
        $Log += "$NewIP is already present; quitting"
        return $Log
    }
    
    if ($Adapter.DefaultGateway.Count -ne 1) {
        $Log += "Not exactly one default gateway on interface; quitting"
        return $Log
    }

    #Check arp to see if the address exists on the subnet already
    [void](ping $NewIP -n 2)
    $Arp = arp -a | Select-String ([regex]::Escape($NewIP.ToString()))
    if ($Arp) {
        $Mac = $Arp -split ' ' | where {$_ -match '([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}'}
        $Log += "$NewIP is assigned to device with MAC address $Mac; quitting"
        return $Log
    }

    $NetworkPrefix = $Adapter.IPAddresses[0].GetNetworkPrefix()
    if ($NetworkPrefix -notlike $Adapter.IPAddresses[-1].GetNetworkPrefix()) {
        $Log += "Multiple subnets on interface; quitting"
        return $Log
    }

    
    $GW = Add-IpAddressMagic -Ip $Adapter.DefaultGateway[0] -Cidr ($NetworkPrefix -replace '^[^/]*/')

    if ($GW.GetNetworkPrefix() -notlike $NetworkPrefix) {
        $Log += "Default gateway not in same subnet; quitting"
        return $Log
    }

    $NewIP = $NewIP | Add-IpAddressMagic -Cidr ($NetworkPrefix -replace '^[^/]*/')

    if ($NewIP.GetNetworkPrefix() -notlike $NetworkPrefix) {
        $Log += "New IP address not in same subnet; quitting"
        return $Log
    }

    $GwCompare = $GW.CompareTo($Adapter.IPAddresses[0]) + $GW.CompareTo($Adapter.IPAddresses[-1])
    if ([Math]::Abs($GwCompare) -ne 2) {
        Must be on the same side as both first and last, and not the same as either
        Example: ([int]1).CompareTo(([int]2)) + ([int]1).CompareTo(([int]9));   ([int]11).CompareTo(([int]2)) + ([int]11).CompareTo(([int]9))
        $Log += "Default gateway falls inside range of existing IP addresses; quitting"
        return $Log
    }

    $NewIPCompare = $NewIP.CompareTo($Adapter.IPAddresses[0]) + $NewIP.CompareTo($Adapter.IPAddresses[-1])
    if ([Math]::Abs($NewIPCompare) -ne 2) {
        $Log += "New IP address falls inside range of existing IP addresses; quitting"
        return $Log
    }

    if (($NewIPCompare + $GwCompare) -ne 0) {
        $Log += "New IP address is closer to default gateway than existing IP addresses; quitting"
        return $Log
    }

    <#
        #Not working (yet)... use netsh instead
        #https://msdn.microsoft.com/en-us/library/aa390383(v=vs.85).aspx
        $EnableStaticErrorLookup = @{
            '0'='Successful completion, no reboot required';
            '1'='Successful completion, reboot required';
            '64'='Method not supported on this platform';
            '65'='Unknown failure';
            '66'='Invalid subnet mask';
            '67'='An error occurred while processing an Instance that was returned';
            '68'='Invalid input parameter';
            '69'='More than 5 gateways specified';
            '70'='Invalid IP address';
            '71'='Invalid gateway IP address';
            '72'='An error occurred while accessing the Registry for the requested information';
            '73'='Invalid domain name';
            '74'='Invalid host name';
            '75'='No primary/secondary WINS server defined';
            '76'='Invalid file';
            '77'='Invalid system path';
            '78'='File copy failed';
            '79'='Invalid security parameter';
            '80'='Unable to configure TCP/IP service';
            '81'='Unable to configure DHCP service';
            '82'='Unable to renew DHCP lease';
            '83'='Unable to release DHCP lease';
            '84'='IP not enabled on adapter';
            '85'='IPX not enabled on adapter';
            '86'='Frame/network number bounds error';
            '87'='Invalid frame type';
            '88'='Invalid network number';
            '89'='Duplicate network number';
            '90'='Parameter out of bounds';
            '91'='Access denied';
            '92'='Out of memory';
            '93'='Already exists';
            '94'='Path, file or object not found';
            '95'='Unable to notify service';
            '96'='Unable to notify DNS service';
            '97'='Interface not configurable';
            '98'='Not all DHCP leases could be released/renewed';
            '100'='DHCP not enabled on adapter';
            '2147786788'='Write lock not enabled. For more information, see INetCfgLock::AcquireWriteLock.'
        }
        #$ReturnVal = $Adapter.WmiConfiguration.EnableStatic(xxxxx)
        #$EnableStaticErrorLookup[([string]$ReturnValue)]
    #>
    netsh interface ip add address $Adapter.Name $NewIP $NewIP.SubnetMask | Out-Null
    Start-Sleep -Milliseconds 500


    $Adapter = Get-WmiAdapter -Identity $Adapter.Name | Add-AdapterMagic
    
    if (($Adapter.IPAddresses | select -ExpandProperty IPAddressToString) -contains $NewIP.IPAddressToString) {
        $Log += "Added $NewIP"
    } else {
        $Log += "Failed to add $NewIP"
    }
    return $Log
}




function Set-DnsServersOnPrimaryAdapter {
    <#
    .Synopsis
        Creates and configures an IP address on the primary network adapter
    
    .Description
        The primary network adapter is defined as the adapter that has the default gateway that has the highest metric.

        This function accepts an IP address and subnet mask, as a [System.Net.IPAddress] that has had extra properties added. To generate this input argument, pass an IP address object to Add-IpAddressMagic and specify either the SubnetMask or Cidr parameter.
    
        This function will not make changes if any of the following checks fail:
            DHCP is disabled
            The new IP address is already present on the adapter
            Multiple default gateways are configured on the adapter
            The new IP address, the default gateway and all the current IP addresses on the adapter are not all in the same subnet
            The new IP address is numerically between existing IP addresses on the adapter
            The new IP address is numerically closer to the default gateway than any existing IP addresses on the adapter
        Part of this is due to the -SkipAsSource behaviour.
    #>

    [CmdletBinding(ConfirmImpact='Medium')]
    [OutputType([void])]

    param(
        [Parameter(Mandatory=$true, Position=0)]
        [ipaddress[]]$DnsServers,
        [switch]$Force
    )

    #https://msdn.microsoft.com/en-us/library/aa393295(v=vs.85).aspx
    $SetDNSServerSearchOrderErrorLookup = @{
        '0'='Successful completion, no reboot required'
        '1'='Successful completion, reboot required'
        '64'='Method not supported on this platform'
        '65'='Unknown failure'
        '66'='Invalid subnet mask'
        '67'='An error occurred while processing an Instance that was returned'
        '68'='Invalid input parameter'
        '69'='More than 5 gateways specified'
        '70'='Invalid IP address'
        '71'='Invalid gateway IP address'
        '72'='An error occurred while accessing the Registry for the requested information'
        '73'='Invalid domain name'
        '74'='Invalid host name'
        '75'='No primary/secondary WINS server defined'
        '76'='Invalid file'
        '77'='Invalid system path'
        '78'='File copy failed'
        '79'='Invalid security parameter'
        '80'='Unable to configure TCP/IP service'
        '81'='Unable to configure DHCP service'
        '82'='Unable to renew DHCP lease'
        '83'='Unable to release DHCP lease'
        '84'='IP not enabled on adapter'
        '85'='IPX not enabled on adapter'
        '86'='Frame/network number bounds error'
        '87'='Invalid frame type'
        '88'='Invalid network number'
        '89'='Duplicate network number'
        '90'='Parameter out of bounds'
        '91'='Access denied'
        '92'='Out of memory'
        '93'='Already exists'
        '94'='Path, file or object not found'
        '95'='Unable to notify service'
        '96'='Unable to notify DNS service'
        '97'='Interface not configurable'
        '98'='Not all DHCP leases could be released/renewed'
        '100'='DHCP not enabled on adapter'
    }

    $Log = @()

    $Adapter = Get-WmiAdapter -Primary | Add-AdapterMagic
    
    #$Log += "Adapter $($Adapter.Name)"

    if ((-not $Force) -and ((Read-Host "Set DNS servers to $($DnsServers -join ', ') on adapter $($Adapter.Name) (Y/N)") -notlike "y")) {
        $Log += "User selected quit"
        return $Log
    }

    if ($Adapter.DHCPEnabled) {
        $Log += "DHCP is enabled; quitting"
        return $Log
    }

    $WmiComputerSystem = Get-WmiObject Win32_ComputerSystem
    $IsPartOfDomain = $WmiComputerSystem.PartOfDomain
    if ($IsPartOfDomain) {$ADDomain = $WmiComputerSystem.Domain} else {$ADDomain = "intensive.int"}
    
    $DnsServerObjs = $DnsServers | foreach {Get-DnsServerObject -IpAddress $_}

    $InvalidServers = $DnsServerObjs | where {-not ($_.ValidateForAdDomain($ADDomain))}
    

    if ($InvalidServers) {
        $Log += (($InvalidServers -join ', ') + " $(if ($InvalidServers.Count -gt 1) {"are"} else {"is"}) not valid for AD domain $ADDomain; quitting")
        return $Log
    }

    $ReturnValue = ($Adapter.WmiConfiguration.SetDNSServerSearchOrder($DnsServers)).ReturnValue   #UInt32

    if ($ReturnValue -eq 0) {
        $Log += "Successfully set DNS Servers to $($DnsServers -join ', ')"
    } else {
        $Log += $SetDNSServerSearchOrderErrorLookup[([string]$ReturnValue)]
    }

    return $Log
}
