<#
.SYNOPSIS
    Deploys a subscription-scoped test initiative and verifies that selected public resources are denied.

.EXAMPLE
    ./tests/deny/Invoke-DenyTest.ps1 -Action All -SubscriptionId 3ec06fc7-1fa1-4d12-b1df-33f5a5153d0a

.EXAMPLE
    ./tests/deny/Invoke-DenyTest.ps1 -Action Destroy -SubscriptionId 3ec06fc7-1fa1-4d12-b1df-33f5a5153d0a -RunId local20261008
#>
[CmdletBinding()]
param(
    [ValidateSet('Validate', 'Deploy', 'Test', 'Destroy', 'All')]
    [string] $Action = 'All',

    [string] $SubscriptionId,

    [string] $Location = 'canadacentral',

    [string] $RunId = (Get-Date -Format 'yyyyMMddHHmmss'),

    [ValidateRange(0, 1800)]
    [int] $PropagationDelaySeconds = 120,

    [switch] $KeepOnFailure
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$PolicyTemplate = Join-Path $PSScriptRoot 'policy-subscription.bicep'
$ResourceTemplate = Join-Path $PSScriptRoot 'test-resources.bicep'
$MatrixPath = Join-Path $PSScriptRoot 'test-matrix.json'
$MainTemplate = Join-Path $RepoRoot 'main.bicep'
$MainParameters = Join-Path $RepoRoot 'main.bicepparam'
$SourceInitiativePath = Join-Path $RepoRoot 'built-in-audit-public-network-access.json'
$CustomDefinitionsPath = Join-Path $RepoRoot 'custom-policy-definitions.json'
$TestMatrix = Get-Content -LiteralPath $MatrixPath -Raw | ConvertFrom-Json -Depth 20

. (Join-Path $PSScriptRoot 'Assert-TestSubscription.ps1')

$normalizedRunId = ($RunId.ToLowerInvariant() -replace '[^a-z0-9]', '')
if ($normalizedRunId.Length -lt 3) {
    throw 'RunId must contain at least three letters or numbers.'
}

$NameSuffix = $normalizedRunId.Substring([Math]::Max(0, $normalizedRunId.Length - [Math]::Min(12, $normalizedRunId.Length)))
$ResourceGroupName = "rg-public-ip-deny-$NameSuffix"
$PolicySetName = "deny-public-ip-smoke-$NameSuffix"
$AssignmentName = "deny-public-ip-$NameSuffix"
$PolicyDeploymentName = "deny-public-ip-policy-$NameSuffix"
$ResultPath = Join-Path $PSScriptRoot "results/$NameSuffix.json"
$ResourceGroupScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"

function Write-Step([string] $Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Invoke-AzCli {
    param(
        [Parameter(Mandatory)]
        [string[]] $Arguments,

        [switch] $Json
    )

    if ($Arguments[0] -ne 'bicep') {
        $Arguments += @('--subscription', $SubscriptionId)
    }

    $output = $null
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        Write-Verbose "az $($Arguments -join ' ')"
        $output = & az @Arguments --only-show-errors 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) {
            break
        }

        $isTransient = $output -match 'ConnectionResetError|Connection aborted|temporarily unavailable|timed out|TooManyRequests|InternalServerError'
        if (-not $isTransient -or $attempt -eq 4) {
            throw "Azure CLI failed: az $($Arguments -join ' ')`n$($output.Trim())"
        }

        Write-Warning "Azure CLI transport failure; retrying in $($attempt * 10) seconds ($attempt/4)."
        Start-Sleep -Seconds ($attempt * 10)
    }

    if ($Json) {
        if ([string]::IsNullOrWhiteSpace($output)) {
            return $null
        }
        return $output | ConvertFrom-Json -Depth 100
    }

    return $output.Trim()
}

function Assert-AzureContext {
    if ($Action -eq 'Validate') {
        return
    }
    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
        throw 'SubscriptionId is required for Azure actions.'
    }

    $script:SubscriptionId = Assert-TestSubscription -SubscriptionId $SubscriptionId
    $script:ResourceGroupScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
}

function Invoke-Validation {
    Write-Step 'Running deny harness validation'

    if ($TestMatrix.schemaVersion -ne 1 -or $TestMatrix.harnessVersion -ne '1.0.0') {
        throw 'Unsupported deny test matrix schema or harness version.'
    }

    $tests = @($TestMatrix.tests)
    if ($tests.Count -ne 3 -or @($tests.key | Sort-Object -Unique).Count -ne $tests.Count) {
        throw 'The deny test matrix must contain three uniquely keyed test cases.'
    }

    $customDefinitions = @(Get-Content -LiteralPath $CustomDefinitionsPath -Raw | ConvertFrom-Json -Depth 100)
    if ($customDefinitions.Count -ne 5) {
        throw "Expected five custom policy definitions, found $($customDefinitions.Count)."
    }
    foreach ($definition in $customDefinitions) {
        if ('Deny' -notin @($definition.properties.parameters.effect.allowedValues)) {
            throw "Custom policy '$($definition.name)' does not allow the Deny effect."
        }
    }
    foreach ($test in $tests) {
        if ($test.policyDefinitionName -notin @($customDefinitions.name)) {
            throw "Test '$($test.key)' references unknown policy '$($test.policyDefinitionName)'."
        }
    }

    $sourceInitiative = Get-Content -LiteralPath $SourceInitiativePath -Raw | ConvertFrom-Json -Depth 100
    $diskEffect = $sourceInitiative.parameters.'Effect-Microsoft.Compute-disks'
    if ('Deny' -in @($diskEffect.allowedValues) -or $diskEffect.defaultValue -ne 'Audit') {
        throw 'The documented Compute disks Audit exception no longer matches the source initiative.'
    }

    & (Join-Path $PSScriptRoot 'Test-TestSubscription.ps1')
    foreach ($template in @($MainTemplate, $PolicyTemplate, $ResourceTemplate)) {
        $null = Invoke-AzCli -Arguments @('bicep', 'build', '--file', $template, '--stdout')
        Write-Host "  [PASS] $(Split-Path $template -Leaf)"
    }
    $null = Invoke-AzCli -Arguments @('bicep', 'build-params', '--file', $MainParameters, '--stdout')
    Write-Host "  [PASS] $(Split-Path $MainParameters -Leaf)"
    Write-Host "  [PASS] test-matrix.json ($($tests.Count) deny cases)"
}

function Register-TestProviders {
    Write-Step 'Registering required resource providers'
    foreach ($provider in @('Microsoft.ApiManagement', 'Microsoft.Authorization', 'Microsoft.Network', 'Microsoft.PolicyInsights')) {
        $state = Invoke-AzCli -Arguments @(
            'provider', 'show',
            '--namespace', $provider,
            '--query', 'registrationState',
            '--output', 'tsv'
        )
        if ($state -ne 'Registered') {
            $null = Invoke-AzCli -Arguments @('provider', 'register', '--namespace', $provider, '--wait')
        }
        Write-Host "  [READY] $provider"
    }
}

function New-AssignmentParameterState($PolicySet) {
    $parameters = [ordered]@{}
    $effectiveValues = [ordered]@{}

    foreach ($property in $PolicySet.parameters.PSObject.Properties) {
        $allowedValues = @($property.Value.allowedValues)
        if ('Deny' -in $allowedValues) {
            $value = 'Deny'
        }
        elseif ($property.Name -eq 'Effect-Microsoft.Compute-disks' -and 'Audit' -in $allowedValues) {
            $value = 'Audit'
        }
        else {
            throw "Initiative parameter '$($property.Name)' does not support Deny and has no approved test exception."
        }

        $parameters[$property.Name] = @{ value = $value }
        $effectiveValues[$property.Name] = $value
    }

    return [pscustomobject]@{
        Json = ($parameters | ConvertTo-Json -Depth 6 -Compress)
        Values = $effectiveValues
    }
}

function Get-PolicySet {
    return Invoke-AzCli -Arguments @(
        'policy', 'set-definition', 'show',
        '--name', $PolicySetName,
        '--output', 'json'
    ) -Json
}

function Get-TestContext {
    $policySet = Get-PolicySet
    $assignments = @(Invoke-AzCli -Arguments @(
        'policy', 'assignment', 'list',
        '--scope', $ResourceGroupScope,
        '--output', 'json'
    ) -Json)
    $assignment = @($assignments | Where-Object name -eq $AssignmentName)
    if ($assignment.Count -ne 1) {
        throw "Expected one policy assignment named '$AssignmentName', found $($assignment.Count)."
    }

    $definitions = @(Invoke-AzCli -Arguments @('policy', 'definition', 'list', '--output', 'json') -Json |
        Where-Object {
            $testRunProperty = $_.metadata.PSObject.Properties['testRunId']
            $testRunProperty -and $testRunProperty.Value -eq $NameSuffix
        })
    if ($definitions.Count -ne 5) {
        throw "Expected five custom definitions for run '$NameSuffix', found $($definitions.Count)."
    }

    $parameterValues = [ordered]@{}
    foreach ($property in $assignment[0].parameters.PSObject.Properties) {
        $parameterValues[$property.Name] = $property.Value.value
    }

    return [pscustomobject]@{
        PolicySet = $policySet
        Assignment = $assignment[0]
        AssignmentParameterValues = $parameterValues
        Definitions = $definitions
    }
}

function Invoke-Deployment {
    Register-TestProviders

    if ((Invoke-AzCli -Arguments @('group', 'exists', '--name', $ResourceGroupName)) -eq 'true') {
        throw "RunId '$RunId' is already in use by resource group '$ResourceGroupName'."
    }

    Write-Step "Creating disposable resource group $ResourceGroupName"
    $expiresOn = (Get-Date).ToUniversalTime().AddHours(6).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $resourceGroup = Invoke-AzCli -Arguments @(
        'group', 'create',
        '--name', $ResourceGroupName,
        '--location', $Location,
        '--tags', 'purpose=public-ip-deny-test', "runId=$RunId", "expiresOn=$expiresOn",
        '--output', 'json'
    ) -Json

    Write-Step "Creating subscription policy set $PolicySetName"
    $null = Invoke-AzCli -Arguments @(
        'deployment', 'sub', 'create',
        '--name', $PolicyDeploymentName,
        '--location', $Location,
        '--template-file', $PolicyTemplate,
        '--parameters', "nameSuffix=$NameSuffix"
    )

    $policySet = Get-PolicySet
    $assignmentParameterState = New-AssignmentParameterState -PolicySet $policySet

    Write-Step 'Assigning every Deny-capable parameter with Deny'
    $null = Invoke-AzCli -Arguments @(
        'policy', 'assignment', 'create',
        '--name', $AssignmentName,
        '--display-name', "Public IP deny test $NameSuffix",
        '--scope', $resourceGroup.id,
        '--policy-set-definition', $policySet.id,
        '--params', $assignmentParameterState.Json,
        '--enforcement-mode', 'Default',
        '--output', 'json'
    ) -Json

    if ($PropagationDelaySeconds -gt 0) {
        Write-Step "Waiting $PropagationDelaySeconds seconds for deny assignment propagation"
        Start-Sleep -Seconds $PropagationDelaySeconds
    }

    return Get-TestContext
}

function Get-ErrorCode([string] $Output) {
    $codeMatch = [regex]::Match($Output, '(?i)"code"\s*:\s*"([^"]+)"')
    if ($codeMatch.Success) {
        return $codeMatch.Groups[1].Value
    }
    if ($Output -match '(?i)RequestDisallowedByPolicy') {
        return 'RequestDisallowedByPolicy'
    }
    return $null
}

function Invoke-DenyAttempt($TestCase) {
    $deploymentName = "deny-$($TestCase.key)-$NameSuffix"
    $expectedDefinitionName = "$($TestCase.policyDefinitionName)-$NameSuffix"
    $startedAt = (Get-Date).ToUniversalTime()

    Write-Step "Expecting policy denial: $($TestCase.description)"
    $arguments = @(
        'deployment', 'group', 'create',
        '--subscription', $SubscriptionId,
        '--resource-group', $ResourceGroupName,
        '--name', $deploymentName,
        '--template-file', $ResourceTemplate,
        '--parameters', "testCase=$($TestCase.key)", "nameSuffix=$NameSuffix", "location=$Location",
        '--only-show-errors'
    )
    Write-Verbose "az $($arguments -join ' ')"
    $output = & az @arguments 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    $completedAt = (Get-Date).ToUniversalTime()
    $policyDenied = $output -match '(?i)RequestDisallowedByPolicy|disallowed by policy|denied by policy'
    $expectedPolicyMatched = $output -match [regex]::Escape($expectedDefinitionName)

    if ($exitCode -eq 0) {
        $status = 'Failed'
        $actualOutcome = 'UnexpectedSuccess'
        Write-Host "  [FAIL] Deployment succeeded; expected Deny from $expectedDefinitionName" -ForegroundColor Red
    }
    elseif ($policyDenied -and $expectedPolicyMatched) {
        $status = 'Passed'
        $actualOutcome = 'Denied'
        Write-Host "  [PASS] Denied by $expectedDefinitionName" -ForegroundColor Green
    }
    elseif ($policyDenied) {
        $status = 'Failed'
        $actualOutcome = 'DeniedByUnexpectedPolicy'
        Write-Host "  [FAIL] Denied, but not by $expectedDefinitionName" -ForegroundColor Red
    }
    else {
        $status = 'Failed'
        $actualOutcome = 'UnexpectedFailure'
        Write-Host '  [FAIL] Deployment failed without a matching Azure Policy denial' -ForegroundColor Red
    }

    $trimmedOutput = $output.Trim()
    if ($trimmedOutput.Length -gt 8000) {
        $trimmedOutput = $trimmedOutput.Substring(0, 8000)
    }

    return [ordered]@{
        key = $TestCase.key
        description = $TestCase.description
        resourceType = $TestCase.resourceType
        expectedOutcome = 'Denied'
        actualOutcome = $actualOutcome
        status = $status
        expectedPolicyDefinitionName = $expectedDefinitionName
        deploymentName = $deploymentName
        startedAt = $startedAt.ToString('o')
        completedAt = $completedAt.ToString('o')
        durationSeconds = [Math]::Round(($completedAt - $startedAt).TotalSeconds, 3)
        azureCliExitCode = $exitCode
        errorCode = Get-ErrorCode -Output $output
        evidence = $trimmedOutput
    }
}

function Invoke-DenyTests {
    $results = @()
    foreach ($testCase in @($TestMatrix.tests)) {
        $results += Invoke-DenyAttempt -TestCase $testCase
    }
    return $results
}

function Get-ToolVersions {
    $azVersion = & az version --output json --only-show-errors 2>$null | ConvertFrom-Json
    $bicepVersion = (& az bicep version 2>$null | Out-String).Trim()

    $gitCommit = $null
    $gitOutput = & git -C $RepoRoot rev-parse HEAD 2>$null | Out-String
    if ($LASTEXITCODE -eq 0) {
        $gitCommit = $gitOutput.Trim()
    }

    return [ordered]@{
        azureCli = $azVersion.'azure-cli'
        azureCliCore = $azVersion.'azure-cli-core'
        bicep = $bicepVersion
        powershell = $PSVersionTable.PSVersion.ToString()
        gitCommit = $gitCommit
    }
}

function Get-ArtifactVersions {
    $artifacts = [ordered]@{}
    foreach ($path in @($MainTemplate, $MainParameters, $SourceInitiativePath, $CustomDefinitionsPath, $PolicyTemplate, $ResourceTemplate, $MatrixPath)) {
        $relativePath = [System.IO.Path]::GetRelativePath($RepoRoot, $path).Replace('\', '/')
        $artifacts[$relativePath] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    return $artifacts
}

function Write-TestResult {
    param(
        [Parameter(Mandatory)]
        [string] $Status,

        $Context,

        [object[]] $TestCases = @(),

        [string] $ErrorMessage
    )

    $resultDirectory = Split-Path $ResultPath -Parent
    $null = New-Item -ItemType Directory -Path $resultDirectory -Force

    $policy = $null
    $assignment = $null
    $definitions = @()
    if ($Context) {
        $policy = [ordered]@{
            id = $Context.PolicySet.id
            name = $Context.PolicySet.name
            displayName = $Context.PolicySet.displayName
            metadataVersion = $Context.PolicySet.metadata.version
            sourcePolicySetDefinitionId = $Context.PolicySet.metadata.sourcePolicySetDefinitionId
            sourcePolicySetDefinitionVersion = $Context.PolicySet.metadata.sourcePolicySetDefinitionVersion
            parameterCount = @($Context.PolicySet.parameters.PSObject.Properties).Count
            policyReferenceCount = @($Context.PolicySet.policyDefinitions).Count
        }
        $assignment = [ordered]@{
            id = $Context.Assignment.id
            name = $Context.Assignment.name
            enforcementMode = $Context.Assignment.enforcementMode
            scope = $Context.Assignment.scope
            parameters = $Context.AssignmentParameterValues
        }
        $definitions = @($Context.Definitions | Sort-Object name | ForEach-Object {
            [ordered]@{
                id = $_.id
                name = $_.name
                displayName = $_.displayName
                version = $_.metadata.version
            }
        })
    }

    $passedCount = @($TestCases | Where-Object status -eq 'Passed').Count
    $failedCount = @($TestCases | Where-Object status -ne 'Passed').Count
    [ordered]@{
        schemaVersion = 1
        harnessVersion = $TestMatrix.harnessVersion
        runId = $RunId
        nameSuffix = $NameSuffix
        subscriptionId = $SubscriptionId
        subscriptionName = 'covallen3-dnstest'
        location = $Location
        resourceGroup = $ResourceGroupName
        status = $Status
        completedAt = (Get-Date).ToUniversalTime().ToString('o')
        error = $ErrorMessage
        summary = [ordered]@{
            total = @($TestCases).Count
            passed = $passedCount
            failed = $failedCount
        }
        policy = $policy
        assignment = $assignment
        customDefinitions = $definitions
        tools = Get-ToolVersions
        artifactSha256 = Get-ArtifactVersions
        testCases = @($TestCases)
    } | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $ResultPath -Encoding utf8

    Write-Host "Result: $ResultPath"
}

function Remove-TestEnvironment {
    Write-Step "Removing deny test environment $NameSuffix"

    $assignments = @(Invoke-AzCli -Arguments @('policy', 'assignment', 'list', '--output', 'json') -Json)
    $assignment = @($assignments | Where-Object {
        $_.name -eq $AssignmentName -and $_.scope -eq $ResourceGroupScope
    })
    if ($assignment.Count -gt 0) {
        $null = Invoke-AzCli -Arguments @(
            'policy', 'assignment', 'delete',
            '--name', $AssignmentName,
            '--scope', $ResourceGroupScope
        )
    }

    if ((Invoke-AzCli -Arguments @('group', 'exists', '--name', $ResourceGroupName)) -eq 'true') {
        $null = Invoke-AzCli -Arguments @('group', 'delete', '--name', $ResourceGroupName, '--yes', '--no-wait')
        Write-Host "  [DELETE STARTED] $ResourceGroupName"
    }

    $policySets = @(Invoke-AzCli -Arguments @('policy', 'set-definition', 'list', '--output', 'json') -Json)
    if (@($policySets | Where-Object name -eq $PolicySetName).Count -gt 0) {
        $null = Invoke-AzCli -Arguments @('policy', 'set-definition', 'delete', '--name', $PolicySetName)
    }

    $definitions = @(Invoke-AzCli -Arguments @('policy', 'definition', 'list', '--output', 'json') -Json)
    foreach ($definition in $definitions | Where-Object {
        $testRunProperty = $_.metadata.PSObject.Properties['testRunId']
        $testRunProperty -and $testRunProperty.Value -eq $NameSuffix
    }) {
        $null = Invoke-AzCli -Arguments @('policy', 'definition', 'delete', '--name', $definition.name)
    }

    $deployments = @(Invoke-AzCli -Arguments @('deployment', 'sub', 'list', '--output', 'json') -Json)
    if (@($deployments | Where-Object name -eq $PolicyDeploymentName).Count -gt 0) {
        $null = Invoke-AzCli -Arguments @('deployment', 'sub', 'delete', '--name', $PolicyDeploymentName)
    }
    Write-Host '  [DONE] Cleanup requests completed.'
}

$null = Get-Command az -ErrorAction Stop
Assert-AzureContext

switch ($Action) {
    'Validate' {
        Invoke-Validation
    }
    'Deploy' {
        $null = Invoke-Deployment
    }
    'Test' {
        $context = Get-TestContext
        $testCases = @(Invoke-DenyTests)
        $failed = @($testCases | Where-Object status -ne 'Passed')
        $status = if ($failed.Count -eq 0) { 'Passed' } else { 'Failed' }
        $errorMessage = if ($failed.Count -eq 0) { $null } else { "$($failed.Count) deny assertion(s) failed." }
        Write-TestResult -Status $status -Context $context -TestCases $testCases -ErrorMessage $errorMessage
        if ($failed.Count -gt 0) {
            throw $errorMessage
        }
    }
    'Destroy' {
        Remove-TestEnvironment
    }
    'All' {
        $context = $null
        $testCases = @()
        $resultWritten = $false
        $testPassed = $false
        try {
            Invoke-Validation
            $context = Invoke-Deployment
            $testCases = @(Invoke-DenyTests)
            $failed = @($testCases | Where-Object status -ne 'Passed')
            if ($failed.Count -gt 0) {
                $message = "$($failed.Count) deny assertion(s) failed."
                Write-TestResult -Status 'Failed' -Context $context -TestCases $testCases -ErrorMessage $message
                $resultWritten = $true
                throw $message
            }

            $testPassed = $true
            Write-TestResult -Status 'Passed' -Context $context -TestCases $testCases -ErrorMessage $null
            $resultWritten = $true
        }
        catch {
            if (-not $resultWritten) {
                Write-TestResult -Status 'Failed' -Context $context -TestCases $testCases -ErrorMessage $_.Exception.Message
            }
            throw
        }
        finally {
            if ($testPassed -or -not $KeepOnFailure) {
                Remove-TestEnvironment
            }
            else {
                Write-Warning "Test resources retained for diagnosis. Run -Action Destroy -RunId '$RunId' to remove them."
            }
        }
    }
}
