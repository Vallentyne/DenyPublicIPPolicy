using './main.bicep'

param initiativeName = 'custom-audit-public-network-access'
param initiativeDisplayName = 'Custom - Audit Public Network Access'

param effectVpnGateways = 'Audit'
param effectAzureFirewalls = 'Audit'
param effectApplicationGateways = 'Audit'
param effectExternalLoadBalancers = 'Audit'
param effectApiManagement = 'Audit'

param effectNatGateways = 'Deny'
param effectBastion = 'Deny'
param effectRouteServer = 'Deny'
param effectApiManagementExternal = 'Deny'
param effectFrontDoor = 'Deny'
