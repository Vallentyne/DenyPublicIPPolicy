using './main.bicep'

param initiativeName = 'audit-public-network-access-custom'
param initiativeDisplayName = 'Audit Public Network Access - Custom'

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
