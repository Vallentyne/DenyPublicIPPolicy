targetScope = 'managementGroup'

@description('Resource name of the custom policy initiative.')
param initiativeName string = 'audit-public-network-access-custom'

@description('Display name of the custom policy initiative.')
param initiativeDisplayName string = 'Audit Public Network Access - Custom'

@allowed([
  'Audit'
  'Deny'
  'Disabled'
])
param effectVpnGateways string = 'Audit'

@allowed([
  'Audit'
  'Deny'
  'Disabled'
])
param effectAzureFirewalls string = 'Audit'

@allowed([
  'Audit'
  'Deny'
  'Disabled'
])
param effectApplicationGateways string = 'Audit'

@allowed([
  'Audit'
  'Deny'
  'Disabled'
])
param effectExternalLoadBalancers string = 'Audit'

@allowed([
  'Audit'
  'Deny'
  'Disabled'
])
param effectApiManagement string = 'Audit'

var sourceInitiative = loadJsonContent('./built-in-audit-public-network-access.json')
var customDefinitions = loadJsonContent('./custom-policy-definitions.json')

var effectParameterDefinition = {
  type: 'String'
  metadata: {
    displayName: 'Effect'
    description: 'Audit, deny, or disable this public network access policy.'
  }
  allowedValues: [
    'Audit'
    'Deny'
    'Disabled'
  ]
  defaultValue: 'Audit'
}

var customPolicyReferences = [for definition in customDefinitions: {
  policyDefinitionReferenceId: definition.referenceId
  policyDefinitionId: extensionResourceId(managementGroup().id, 'Microsoft.Authorization/policyDefinitions', definition.name)
  parameters: {
    effect: {
      value: '[[parameters(\'${definition.initiativeParameter}\')]'
    }
  }
}]

resource customPolicies 'Microsoft.Authorization/policyDefinitions@2023-04-01' = [for definition in customDefinitions: {
  name: definition.name
  properties: definition.properties
}]

resource customInitiative 'Microsoft.Authorization/policySetDefinitions@2023-04-01' = {
  name: initiativeName
  properties: {
    policyType: 'Custom'
    displayName: initiativeDisplayName
    description: 'Extends the built-in Audit Public Network Access initiative version ${sourceInitiative.metadata.version} with VPN Gateway, Azure Firewall, Application Gateway, external Load Balancer, and API Management checks.'
    metadata: {
      category: 'Network'
      version: '1.0.0'
      sourcePolicySetDefinitionId: sourceInitiative.id
      sourcePolicySetDefinitionVersion: sourceInitiative.metadata.version
    }
    parameters: union(sourceInitiative.parameters, {
      'Effect-VpnGateway': union(effectParameterDefinition, {
        defaultValue: effectVpnGateways
      })
      'Effect-AzureFirewall': union(effectParameterDefinition, {
        defaultValue: effectAzureFirewalls
      })
      'Effect-ApplicationGateway': union(effectParameterDefinition, {
        defaultValue: effectApplicationGateways
      })
      'Effect-ExternalLoadBalancer': union(effectParameterDefinition, {
        defaultValue: effectExternalLoadBalancers
      })
      'Effect-ApiManagement': union(effectParameterDefinition, {
        defaultValue: effectApiManagement
      })
    })
    policyDefinitions: concat(sourceInitiative.policyDefinitions, customPolicyReferences)
  }
  dependsOn: [
    customPolicies
  ]
}

output customInitiativeId string = customInitiative.id
output sourceInitiativeVersion string = sourceInitiative.metadata.version
