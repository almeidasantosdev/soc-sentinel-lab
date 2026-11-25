# Dados sintéticos

Todos os eventos desta pasta são fictícios. As pessoas, os domínios `contoso-lab.example` e os endereços das redes de documentação `192.0.2.0/24`, `198.51.100.0/24` e `203.0.113.0/24` não representam um tenant.

Não há segredo, identificador de diretório real nem cópia de log de produção.

## O que cada arquivo representa

| Arquivo | Tabela canônica | Uso na regra |
| --- | --- | --- |
| `signinlogs.json` e `.csv` | `SigninLogs` | Força bruta, spray, viagem impossível e caçadas de entrada |
| `auditlogs.json` | `AuditLogs` | Função privilegiada |
| `securityevent.json` e `.csv` | `SecurityEvent` | Exclusão em massa, logon e PowerShell |
| `commonsecuritylog.json` e `.csv` | `CommonSecurityLog` | Porta administrativa e volume de saída |
| `urlclickevents.json` e `.csv` | `UrlClickEvents` | Clique de phishing |

O subconjunto de colunas é o que as consultas deste repositório leem. Não é o schema completo do conector.

## Testar sem tenant, com `datatable()`

Cada regra e cada caçada tem uma cópia em `runnable/`. O arquivo abre com `let Tabela = datatable(...)` e, em seguida, a consulta original. No Kusto, esse `let` vale só para a execução: nada é gravado.

1. Abra o portal do Log Analytics ou um cluster gratuito do Azure Data Explorer.
2. Cole `sample-data/runnable/<nome>.kql`.
3. Execute. A consulta que deveria alertar devolve as linhas do cenário sintético.

O horário dos eventos é 16 de março de 2026. As regras agendadas não filtram `ago()`, porque o Sentinel aplica `queryPeriod`. Por isso o teste com `datatable()` não depende do dia em que você executa.

## Persistir em tabela de laboratório

`adx/create-and-ingest.kql` contém comandos de controle do Azure Data Explorer. Eles criam tabelas com prefixo `Lab` e ingerem o JSON sintético. Não rode esse arquivo no lint de consulta: comando de controle não é KQL de alerta.

No Microsoft Sentinel, nomes como `SigninLogs` pertencem ao conector. Se o conector já existe, não tente recriar a tabela. Crie uma tabela customizada com outro nome, ou continue no `datatable()`.

Para uma regra implantada de verdade, use o conector correspondente num workspace vazio de estudo. Os modelos em `detections/arm/` nascem desligados.

## O que a amostra deve devolver

| Consulta | Deve aparecer | Não deve aparecer |
| --- | --- | --- |
| Força bruta | `ana.costa` a partir de `203.0.113.10` | as duas falhas de `bruno.lima` |
| Password spray | `198.51.100.23` | o IP da força bruta, que atinge uma conta só |
| Viagem impossível | `carla.nunes`, Brasil e depois Japão em 35 minutos | `diego.souza`, Brasil e Portugal com 10 horas de intervalo |
| Porta administrativa | `203.0.113.40` para `10.10.10.20` | o RDP interno de `10.10.10.5` |
| Exclusão em massa | `CONTOSO\svc-backup` com 30 arquivos | as duas exclusões de `ana.costa` |
| Volume de saída | 250000000 bytes para `203.0.113.80` | os 20000 bytes para `192.0.2.40` |
| Função privilegiada | Global Administrator de Bruno e User Administrator de Diego | Directory Readers e a tentativa com falha |
| Phishing | `login-verify.example.xyz` e `micr0soft-secure.top` | intranet, `learn.microsoft.com` e o clique bloqueado |

`learn.microsoft.com` continua na caçada de domínios externos. A regra de phishing não trata esse domínio como suspeito. O clique bloqueado para `.ru` também fica só na caçada: o controle já segurou o acesso.
