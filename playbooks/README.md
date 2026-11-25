# Playbooks e runbooks

O arquivo `enrich-ip-notify.json` é um modelo ARM de Logic App para laboratório.

O fluxo faz quatro coisas quando um incidente do Microsoft Sentinel é criado:

1. Lê as entidades de IP do incidente.
2. Consulta um serviço de enriquecimento configurável. O padrão aponta para um serviço público sem chave e só serve para IP de exercício.
3. Comenta o incidente com país e cidade e publica uma linha no Teams pelo webhook informado na implantação.
4. Envia um e-mail com número, severidade e descrição.

O fluxo não desativa usuário, não bloqueia IP e não altera função. Contenção fica nos runbooks, com decisão do N2.

## Implantar

Autorize as conexões `azuresentinel` e `office365` no portal depois do deploy. O webhook do Teams entra como parâmetro `TeamsWebhookUrl` e não fica gravado neste repositório.

```bash
az deployment group create \
  --resource-group rg-sentinel-lab \
  --template-file playbooks/enrich-ip-notify.json \
  --parameters TeamsWebhookUrl="$TEAMS_WEBHOOK_URL" NotificationEmail="soc-lab@contoso-lab.example"
```

Troque `EnrichmentBaseUrl` antes de apontar o fluxo para incidente real. A URL precisa terminar com barra.

## Runbooks

Cada regra em `detections/` tem um runbook em `playbooks/runbooks/` com o mesmo nome. O texto traz o passo do N1, o prazo e o que entregar na escalação para o N2.
