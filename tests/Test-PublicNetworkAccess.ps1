#requires -Version 7.0
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$definitions = @(Get-Content (Join-Path $root 'custom-policy-definitions.json') -Raw | ConvertFrom-Json -AsHashtable)

function Assert-True {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) {
        throw $Message
    }
}

# Fixtures supply resolved alias values, not ARM requests. Azure must still
# validate aliases, resource modes, and actual deployment enforcement.
function Test-Condition {
    param([System.Collections.IDictionary] $Condition, [hashtable] $Fields)
    if ($Condition.Contains('allOf')) {
        foreach ($child in $Condition.allOf) {
            if (-not (Test-Condition $child $Fields)) { return $false }
        }
        return $true
    }
    if ($Condition.Contains('anyOf')) {
        foreach ($child in $Condition.anyOf) {
            if (Test-Condition $child $Fields) { return $true }
        }
        return $false
    }
    if ($Condition.Contains('count')) {
        Assert-True ($Condition.Contains('greater') -and $Condition.count.Keys.Count -eq 1) 'Unsupported count condition'
        return @($Fields[$Condition.count.field]).Where({ $null -ne $_ }).Count -gt $Condition.greater
    }
    Assert-True ($Condition.Contains('field')) 'Unsupported condition'
    $value = $Fields[$Condition.field]
    if ($Condition.Contains('exists')) {
        return ($Fields.ContainsKey($Condition.field) -and $null -ne $value) -eq $Condition.exists
    }
    if ($Condition.Contains('equals')) { return $value -eq $Condition.equals }
    if ($Condition.Contains('notEquals')) { return $value -ne $Condition.notEquals }
    if ($Condition.Contains('in')) { return $value -in $Condition.in }
    throw 'Unsupported condition operator'
}

$policies = @{}
foreach ($definition in $definitions) {
    $policies[$definition.name] = $definition
}

$cases = @(
    @{ Policy = 'audit-deny-nat-gateway-public-ip'; Label = 'no associations'; Type = 'Microsoft.Network/natGateways'; Fields = @{}; Match = $false }
    @{ Policy = 'audit-deny-bastion-public-access'; Label = 'private-only Premium'; Type = 'Microsoft.Network/bastionHosts'; Fields = @{ 'Microsoft.Network/bastionHosts/enablePrivateOnlyBastion' = $true }; Match = $false }
    @{ Policy = 'audit-deny-bastion-public-access'; Label = 'public Bastion'; Type = 'Microsoft.Network/bastionHosts'; Fields = @{ 'Microsoft.Network/bastionHosts/enablePrivateOnlyBastion' = $false }; Match = $true }
    @{ Policy = 'audit-deny-bastion-public-access'; Label = 'omitted private-only flag / Developer'; Type = 'Microsoft.Network/bastionHosts'; Fields = @{}; Match = $true }
    @{ Policy = 'audit-deny-route-server-public-ip'; Label = 'standalone Route Server parent'; Type = 'Microsoft.Network/virtualHubs'; Fields = @{}; Match = $true }
    @{ Policy = 'audit-deny-route-server-public-ip'; Label = 'Virtual WAN hub'; Type = 'Microsoft.Network/virtualHubs'; Fields = @{ 'Microsoft.Network/virtualHubs/virtualWan.id' = '/virtualWans/test' }; Match = $false }
    @{ Policy = 'audit-deny-route-server-public-ip'; Label = 'public IP on existing Route Server'; Type = 'Microsoft.Network/virtualHubs/ipConfigurations'; Fields = @{ 'Microsoft.Network/virtualHubs/ipConfigurations/publicIPAddress.id' = '/publicIPAddresses/test' }; Match = $true }
    @{ Policy = 'audit-deny-route-server-public-ip'; Label = 'private IP configuration'; Type = 'Microsoft.Network/virtualHubs/ipConfigurations'; Fields = @{}; Match = $false }
    @{ Policy = 'audit-deny-apim-external-mode'; Label = 'External even with PNA disabled'; Type = 'Microsoft.ApiManagement/service'; Fields = @{ 'Microsoft.ApiManagement/service/virtualNetworkType' = 'External'; 'Microsoft.ApiManagement/service/publicNetworkAccess' = 'Disabled' }; Match = $true }
    @{ Policy = 'audit-deny-apim-external-mode'; Label = 'Internal with PNA enabled'; Type = 'Microsoft.ApiManagement/service'; Fields = @{ 'Microsoft.ApiManagement/service/virtualNetworkType' = 'Internal'; 'Microsoft.ApiManagement/service/publicNetworkAccess' = 'Enabled' }; Match = $false }
    @{ Policy = 'audit-deny-apim-external-mode'; Label = 'None'; Type = 'Microsoft.ApiManagement/service'; Fields = @{ 'Microsoft.ApiManagement/service/virtualNetworkType' = 'None' }; Match = $false }
    @{ Policy = 'audit-deny-apim-external-mode'; Label = 'omitted network mode'; Type = 'Microsoft.ApiManagement/service'; Fields = @{}; Match = $false }
    @{ Policy = 'audit-deny-front-door'; Label = 'Classic'; Type = 'Microsoft.Network/frontDoors'; Fields = @{}; Match = $true }
    @{ Policy = 'audit-deny-front-door'; Label = 'Standard'; Type = 'Microsoft.Cdn/profiles'; Fields = @{ 'Microsoft.CDN/profiles/sku.name' = 'Standard_AzureFrontDoor' }; Match = $true }
    @{ Policy = 'audit-deny-front-door'; Label = 'Premium with private origin'; Type = 'Microsoft.Cdn/profiles'; Fields = @{ 'Microsoft.CDN/profiles/sku.name' = 'Premium_AzureFrontDoor' }; Match = $true }
    @{ Policy = 'audit-deny-front-door'; Label = 'unrelated CDN profile'; Type = 'Microsoft.Cdn/profiles'; Fields = @{ 'Microsoft.CDN/profiles/sku.name' = 'Standard_Microsoft' }; Match = $false }
    @{ Policy = 'audit-deny-front-door'; Label = 'endpoint on existing profile'; Type = 'Microsoft.Cdn/profiles/afdEndpoints'; Fields = @{}; Match = $true }
    @{ Policy = 'audit-deny-front-door'; Label = 'non-Front Door CDN endpoint'; Type = 'Microsoft.Cdn/profiles/endpoints'; Fields = @{}; Match = $false }
)
foreach ($alias in 'publicIpAddresses', 'publicIpPrefixes', 'publicIpAddressesV6', 'publicIpPrefixesV6') {
    foreach ($populated in $false, $true) {
        $values = if ($populated) { @(@{ id = '/publicIPResources/test' }) } else { @() }
        $cases += @{ Policy = 'audit-deny-nat-gateway-public-ip'; Label = "$alias populated=$populated"; Type = 'Microsoft.Network/natGateways'; Fields = @{ "Microsoft.Network/natGateways/$alias`[*]" = $values }; Match = $populated }
    }
}
foreach ($name in @($cases.Policy | Sort-Object -Unique)) {
    Assert-True ($policies.ContainsKey($name)) "Missing policy $name"
    $cases += @{ Policy = $name; Label = 'unrelated resource'; Type = 'Microsoft.Storage/storageAccounts'; Fields = @{}; Match = $false }
}
foreach ($case in $cases) {
    $case.Fields.type = $case.Type
    $actual = Test-Condition $policies[$case.Policy].properties.policyRule.if $case.Fields
    Assert-True ($actual -eq $case.Match) "$($case.Policy): $($case.Label) expected match=$($case.Match), got $actual"
}
Write-Host "Passed $($cases.Count) offline rule cases."
