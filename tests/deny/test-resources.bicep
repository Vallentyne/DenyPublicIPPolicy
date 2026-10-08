targetScope = 'resourceGroup'

@allowed([
  'apiManagement'
  'applicationGateway'
  'loadBalancer'
])
param testCase string

@description('Short identifier shared by all resources in a test run.')
@minLength(3)
@maxLength(12)
param nameSuffix string

param location string = resourceGroup().location

var isApplicationGateway = testCase == 'applicationGateway'
var isLoadBalancer = testCase == 'loadBalancer'
var requiresPublicIp = isApplicationGateway || isLoadBalancer
var resourceSuffix = uniqueString(subscription().subscriptionId, resourceGroup().id, nameSuffix, testCase)

resource publicIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = if (requiresPublicIp) {
  name: 'pip-${testCase}-${nameSuffix}'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2024-05-01' = if (isApplicationGateway) {
  name: 'vnet-appgw-${nameSuffix}'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.84.0.0/16'
      ]
    }
  }
}

resource applicationGatewaySubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = if (isApplicationGateway) {
  parent: virtualNetwork
  name: 'application-gateway'
  properties: {
    addressPrefix: '10.84.1.0/24'
  }
}

resource loadBalancer 'Microsoft.Network/loadBalancers@2024-05-01' = if (isLoadBalancer) {
  name: 'lb-deny-${nameSuffix}'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    frontendIPConfigurations: [
      {
        name: 'public'
        properties: {
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
  }
}

resource applicationGateway 'Microsoft.Network/applicationGateways@2024-05-01' = if (isApplicationGateway) {
  name: 'agw-deny-${nameSuffix}'
  location: location
  properties: {
    backendAddressPools: [
      {
        name: 'empty'
        properties: {}
      }
    ]
    backendHttpSettingsCollection: [
      {
        name: 'http'
        properties: {
          cookieBasedAffinity: 'Disabled'
          port: 80
          protocol: 'Http'
          requestTimeout: 20
        }
      }
    ]
    frontendIPConfigurations: [
      {
        name: 'public'
        properties: {
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
    frontendPorts: [
      {
        name: 'http'
        properties: {
          port: 80
        }
      }
    ]
    gatewayIPConfigurations: [
      {
        name: 'gateway'
        properties: {
          subnet: {
            id: applicationGatewaySubnet.id
          }
        }
      }
    ]
    httpListeners: [
      {
        name: 'http'
        properties: {
          frontendIPConfiguration: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendIPConfigurations', 'agw-deny-${nameSuffix}', 'public')
          }
          frontendPort: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendPorts', 'agw-deny-${nameSuffix}', 'http')
          }
          protocol: 'Http'
        }
      }
    ]
    requestRoutingRules: [
      {
        name: 'default'
        properties: {
          backendAddressPool: {
            id: resourceId('Microsoft.Network/applicationGateways/backendAddressPools', 'agw-deny-${nameSuffix}', 'empty')
          }
          backendHttpSettings: {
            id: resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', 'agw-deny-${nameSuffix}', 'http')
          }
          httpListener: {
            id: resourceId('Microsoft.Network/applicationGateways/httpListeners', 'agw-deny-${nameSuffix}', 'http')
          }
          priority: 100
          ruleType: 'Basic'
        }
      }
    ]
    sku: {
      capacity: 1
      name: 'Standard_v2'
      tier: 'Standard_v2'
    }
  }
}

resource apiManagement 'Microsoft.ApiManagement/service@2024-05-01' = if (testCase == 'apiManagement') {
  name: 'apim-deny-${resourceSuffix}'
  location: location
  sku: {
    capacity: 1
    name: 'Developer'
  }
  properties: {
    publisherEmail: 'policy-test@example.com'
    publisherName: 'Policy Test'
    publicNetworkAccess: 'Enabled'
    virtualNetworkType: 'None'
  }
}
