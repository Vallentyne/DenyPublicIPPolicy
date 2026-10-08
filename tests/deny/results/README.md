# Deny test results

Each live test run writes one JSON file named after its normalized run ID. Commit useful results so policy, harness, Azure CLI, Bicep, PowerShell, source initiative, custom definition, assignment parameter, and per-resource denial evidence remain available for comparison.

The result schema is versioned independently from the policy definitions. Failed runs are retained too, including unexpected successful deployments and failures that were not caused by Azure Policy.
