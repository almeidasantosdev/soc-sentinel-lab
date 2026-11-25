# Infraestrutura de laboratório

`main.bicep` cria um workspace de Log Analytics e habilita o Microsoft Sentinel no grupo de recursos atual. O teto diário fica em 1 GB e a retenção em 30 dias para reduzir custo de um estudo.

Isto não conecta tenant de produção, não cria regra e não ingere os arquivos de `sample-data/`. As regras continuam desligadas nos modelos ARM em `detections/arm/`.

Há custo mesmo em assinatura de desenvolvimento. Apague o grupo de recursos ao fim do exercício.

```bash
az group create --name rg-sentinel-lab --location brazilsouth
az deployment group create \
  --resource-group rg-sentinel-lab \
  --template-file infra/main.bicep \
  --parameters infra/dev.bicepparam
```

Use uma assinatura que você possa apagar. Não reaproveite um workspace que já recebe log real.
