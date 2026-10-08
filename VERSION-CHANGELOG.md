# Version changelog

## Policy 1.0.0

- Based on Microsoft built-in **Audit Public Network Access** initiative version 4.3.0.
- Adds VPN Gateway, Azure Firewall, Application Gateway, external Load Balancer, and API Management policies.
- Supports `Audit`, `Deny`, and `Disabled` independently for each added policy.

## Deny harness 1.0.0

- Creates run-specific subscription-scoped policy definitions and an initiative in `covallen3-dnstest`.
- Assigns `Deny` to every parameter that permits it.
- Retains `Audit` for the built-in Compute disks policy because that definition does not support `Deny`.
- Verifies expected denials for external Load Balancer, Application Gateway, and API Management deployments.
- Records tool, source, deployed policy, assignment, artifact hash, and per-test evidence in versioned JSON results.
