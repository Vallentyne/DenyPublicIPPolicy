[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Assert-TestSubscription.ps1')

$testSubscriptionId = '11111111-1111-1111-1111-111111111111'
$accountResponse = @{ id = $testSubscriptionId; name = 'covallen3-dnstest'; state = 'Enabled' }
$cliExitCode = 0

function az {
    $global:LASTEXITCODE = $cliExitCode
    $accountResponse | ConvertTo-Json -Compress
}

foreach ($requested in @($testSubscriptionId, 'covallen3-dnstest')) {
    if ((Assert-TestSubscription -SubscriptionId $requested) -ne $testSubscriptionId) {
        throw 'The allowed subscription must resolve to its GUID.'
    }
}

$accountResponse.name = 'production'
try {
    $null = Assert-TestSubscription -SubscriptionId $testSubscriptionId
    throw 'Expected the production subscription to be rejected.'
}
catch {
    if ($_.Exception.Message -notlike '*Deny tests may only use subscription*') { throw }
}

$accountResponse.name = 'covallen3-dnstest'
$accountResponse.state = 'Disabled'
try {
    $null = Assert-TestSubscription -SubscriptionId $testSubscriptionId
    throw 'Expected the disabled subscription to be rejected.'
}
catch {
    if ($_.Exception.Message -notlike '*is not enabled*') { throw }
}

$accountResponse.state = 'Enabled'
$accountResponse.id = 'invalid'
try {
    $null = Assert-TestSubscription -SubscriptionId $testSubscriptionId
    throw 'Expected the invalid subscription ID to be rejected.'
}
catch {
    if ($_.Exception.Message -notlike '*invalid subscription ID*') { throw }
}

$accountResponse.id = $testSubscriptionId
$cliExitCode = 1
try {
    $null = Assert-TestSubscription -SubscriptionId $testSubscriptionId
    throw 'Expected the failed Azure CLI lookup to be rejected.'
}
catch {
    if ($_.Exception.Message -notlike '*Unable to verify deny-test subscription*') { throw }
}

$global:LASTEXITCODE = 0
Write-Host '  [PASS] Deny-test subscription guard'
