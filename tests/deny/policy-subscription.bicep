targetScope = 'subscription'

@description('Short, lowercase identifier that isolates this test run.')
@minLength(3)
@maxLength(12)
param nameSuffix string

@description('Display name of the disposable test initiative.')
param initiativeDisplayName string = 'Deny Public Network Access - Test ${nameSuffix}'

var sourceInitiative = loadJsonContent('../../built-in-audit-public-network-access.json')
var customDefinitions = loadJsonContent('../../custom-policy-definitions.json')
var initiativeName = 'deny-public-ip-smoke-${nameSuffix}'

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
  defaultValue: 'Deny'
}

var customPolicyReferences = [for definition in customDefinitions: {
  policyDefinitionReferenceId: definition.referenceId
  policyDefinitionId: subscriptionResourceId('Microsoft.Authorization/policyDefinitions', '${definition.name}-${nameSuffix}')
  parameters: {
    effect: {
      value: '[[parameters(\'${definition.initiativeParameter}\')]'
    }
  }
}]

resource customPolicies 'Microsoft.Authorization/policyDefinitions@2023-04-01' = [for definition in customDefinitions: {
  name: '${definition.name}-${nameSuffix}'
  properties: union(definition.properties, {
    metadata: union(definition.properties.metadata, {
      testRunId: nameSuffix
    })
  })
}]

resource testInitiative 'Microsoft.Authorization/policySetDefinitions@2023-04-01' = {
  name: initiativeName
  properties: {
    policyType: 'Custom'
    displayName: initiativeDisplayName
    description: 'Disposable deny-effect test copy of Audit Public Network Access ${sourceInitiative.metadata.version}.'
    metadata: {
      category: 'Network'
      version: '1.0.0-test'
      harnessVersion: '1.0.0'
      testRunId: nameSuffix
      sourcePolicySetDefinitionId: sourceInitiative.id
      sourcePolicySetDefinitionVersion: sourceInitiative.metadata.version
    }
    parameters: union(sourceInitiative.parameters, {
      'Effect-VpnGateway': effectParameterDefinition
      'Effect-AzureFirewall': effectParameterDefinition
      'Effect-ApplicationGateway': effectParameterDefinition
      'Effect-ExternalLoadBalancer': effectParameterDefinition
      'Effect-ApiManagement': effectParameterDefinition
    })
    policyDefinitions: concat(sourceInitiative.policyDefinitions, customPolicyReferences)
  }
  dependsOn: [
    customPolicies
  ]
}

output customDefinitionIds array = [for (definition, index) in customDefinitions: customPolicies[index].id]
output initiativeId string = testInitiative.id
output initiativeName string = testInitiative.name
output sourceInitiativeVersion string = sourceInitiative.metadata.version
