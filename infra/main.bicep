targetScope = 'resourceGroup'

@description('Região dos recursos. O padrão acompanha o grupo de recursos.')
param location string = resourceGroup().location

@description('Nome do workspace de laboratório. Não reutilize um workspace de produção.')
param workspaceName string = 'law-sentinel-lab'

@description('Retenção curta, suficiente para o exercício.')
@minValue(30)
@maxValue(90)
param retentionInDays int = 30

@description('Teto diário em GB para reduzir custo acidental.')
@minValue(1)
@maxValue(5)
param dailyQuotaGb int = 1

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
    workspaceCapping: {
      dailyQuotaGb: dailyQuotaGb
    }
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

resource sentinel 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = {
  name: 'SecurityInsights(${workspace.name})'
  location: location
  properties: {
    workspaceResourceId: workspace.id
  }
  plan: {
    name: 'SecurityInsights(${workspace.name})'
    publisher: 'Microsoft'
    product: 'OMSGallery/SecurityInsights'
    promotionCode: ''
  }
}

output workspaceId string = workspace.id
output workspaceName string = workspace.name
