# Custom Audit Public Network Access initiative

This deployment creates a management-group-scoped custom Azure Policy initiative based on the Microsoft built-in **Audit Public Network Access** initiative:

`/providers/Microsoft.Authorization/policySetDefinitions/f1535064-3294-48fa-94e2-6e83095a5c08`

The checked-in source snapshot is version **4.3.0**. The deployment preserves its 34 policy references and adds configurable policies for:

- Azure VPN gateways
- Azure Firewalls
- Application Gateways
- External Load Balancers
- API Management services

Each added policy accepts `Audit`, `Deny`, or `Disabled`. The parameter file defaults all five to `Audit`.

## Important enforcement considerations

- VPN gateways normally require public IP addresses. Use `Deny` only where your approved architecture does not require a public VPN endpoint.
- Azure Firewall public IP requirements vary by architecture. Validate forced-tunneling and secured virtual hub designs before selecting `Deny`.
- Changing an initiative parameter to `Deny` affects new or updated resources. Existing noncompliant resources remain visible but are not automatically remediated.
- The API Management policy evaluates the service-level `publicNetworkAccess` property. This is broader than the built-in policy that audits individual service configuration endpoints.

## Validate

```powershell
az bicep build --file .\main.bicep
```

Preview the management group deployment:

```powershell
az deployment mg what-if `
  --management-group-id <management-group-id> `
  --location <deployment-location> `
  --template-file .\main.bicep `
  --parameters .\main.bicepparam
```

Deploy:

```powershell
az deployment mg create `
  --name deploy-custom-public-network-access-initiative `
  --management-group-id <management-group-id> `
  --location <deployment-location> `
  --template-file .\main.bicep `
  --parameters .\main.bicepparam
```

The template creates the definitions and initiative only. Assign the resulting initiative separately at the intended management group, subscription, or resource group scope.

## Deny test harness

The deny harness follows the disposable test pattern used by the PrivateLink DNS policy set. It is hard-locked to the `covallen3-dnstest` subscription and performs these steps:

1. Validates the Bicep templates, test matrix, shared policy definitions, and subscription guard.
2. Creates run-specific copies of the five custom policy definitions and the full policy initiative at subscription scope.
3. Creates a disposable resource group and assigns the initiative to it.
4. Sets every initiative parameter that supports `Deny` to `Deny`.
5. Keeps `Effect-Microsoft.Compute-disks` at `Audit`, because the Microsoft built-in definition only accepts `Audit` or `Disabled`.
6. Attempts deployments for an external Load Balancer, Application Gateway, and API Management service.
7. Passes each assertion only when Azure returns a policy denial from the expected run-specific custom definition.
8. Writes a versioned JSON result and removes the assignment, resource group, policy set, custom definitions, and deployment record.

Run static validation without changing Azure:

```powershell
.\tests\deny\Invoke-DenyTest.ps1 -Action Validate
```

Run the complete live test:

```powershell
.\tests\deny\Invoke-DenyTest.ps1 `
  -Action All `
  -SubscriptionId 3ec06fc7-1fa1-4d12-b1df-33f5a5153d0a `
  -Location canadacentral
```

To retain a failed environment for diagnosis:

```powershell
.\tests\deny\Invoke-DenyTest.ps1 `
  -Action All `
  -SubscriptionId 3ec06fc7-1fa1-4d12-b1df-33f5a5153d0a `
  -KeepOnFailure
```

Clean up a retained run using the same run ID:

```powershell
.\tests\deny\Invoke-DenyTest.ps1 `
  -Action Destroy `
  -SubscriptionId 3ec06fc7-1fa1-4d12-b1df-33f5a5153d0a `
  -RunId <retained-run-id>
```

Results are written under `tests/deny/results`. Each result captures:

- Result and harness schema versions
- Built-in source initiative ID and version
- Deployed initiative metadata and policy reference count
- Custom policy definition IDs and versions
- The complete effective assignment parameter map
- Azure CLI, Bicep, PowerShell, and Git versions
- SHA-256 hashes for all policy and test inputs
- Per-resource denial outcome, expected policy, error code, duration, and Azure error evidence

Download CI result artifacts and commit useful pass and failure records to preserve a long-term test history.
