# Version changelog

## Policy 1.1.0

- Matches EPAC coverage with 44 references: 34 built-ins and ten custom policies.
- Adds NAT Gateway public IPv4/IPv6 address and prefix associations, public Bastion, Route Server, APIM External mode, and Front Door checks.
- Defaults the five additions to `Deny` in the initiative template and parameter file; the original five remain `Audit`.
- Retains `Audit` defaults on individual custom policy definitions.

## Deny harness 1.1.0

- Deploys and validates all ten custom definitions and their initiative effect parameters.
- Adds offline positive and negative rule tests for the five additions.
- Keeps the existing three-case live deployment matrix; Azure enforcement of the new checks has not been live-tested by this update.

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
