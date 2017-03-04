<#
    .AUTHOR
    Copyright Freddie Sackur 2017
    https://github.com/fsackur/LegacyNetAdapter
#>

function Add-DefaultMembers {
    <#
        .Synopsis
        Applies formatting data to a custom object
        
        .Description
        This works by pass-by-reference - the original object is updated. If you want to have an object returned, use the -PassThru switch.

        Please note that most default objects will not work if they are of a standard pre-defined type. You can convert them by piping them to a select statement.

            #This will throw an exception:
            Get-Process svchost | select * | Add-DefaultMembers -DisplayProperties 'ProcessName', 'Id'

            #This will work, but you will lose the built-in methods:
            Get-Process svchost | select * | Add-DefaultMembers -DisplayProperties 'ProcessName', 'Id' -PassThru


        .Inputs
        InputObject: The object to be configured with custom properties

        DisplayProperties: An array of property names that will be displayed on the object by default

        SortProperties: An array of property names that will determine sorting, in order of precedence

        PassThru: specifies to return the updated object to the pipeline (by default it is not returned; either way, the original reference is updated)
    #>
    [CmdletBinding(DefaultParameterSetName='Default')]
    [OutputType([void], ParameterSetName='Default')]
    [OutputType([psobject], ParameterSetName='PassThru')]
    param(
        [Parameter(Position=0, ValueFromPipeline=$true)]
        [psobject]$InputObject,
        [Parameter(Position=1)]
        [string[]]$DisplayProperties,
        [Parameter(Position=2)]
        [string[]]$SortProperties,
        [string]$TypeName,
        [Parameter(Mandatory=$true, ParameterSetName='PassThru')]
        [switch]$PassThru
    )

    if ($TypeName) {$InputObject.PSTypeNames.Insert(0, $TypeName)}
    
    if ($DisplayProperties) {
        $Display = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', $DisplayProperties)
    }
    if ($SortProperties) {
        $Sort =    New-Object System.Management.Automation.PSPropertySet('DefaultKeyPropertySet', $SortProperties)
    }

    $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($Display, $Sort)

    try {
        Add-Member -InputObject $InputObject -MemberType MemberSet -Name PSStandardMembers `
            -Value $PSStandardMembers -Force -ErrorAction Stop
    } catch {
        if ($_ -match 'Cannot force the member with name "PSStandardMembers" and type "MemberSet" to be added. A member with that name and type already exists, and the existing member is not an instance extension.') {
            throw (New-Object System.ArgumentException (
                "Cannot add new default members to a fixed object type. Try running your input object through a select statement first."
            ))
        } else {
            throw $_
        }
    }

    if ($PassThru) {return $InputObject}
}
