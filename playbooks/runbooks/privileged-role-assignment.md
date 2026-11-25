# Nova atribuição de função privilegiada

Regra: `detections/privileged-role-assignment.yaml`  
MITRE: T1098, T1098.003  
Severidade: High

## Objetivo

Confirmar se a inclusão em função privilegiada do Entra ID estava prevista em mudança ou se é persistência.

## SLA

- N1 inicia a triagem em 15 minutos após o incidente.
- Se não houver mudança aprovada, escala para o N2 em 30 minutos.
- O relógio conta a partir da criação do incidente no Sentinel.

## Passos do N1

1. Leia a conta alvo, a função e quem executou a ação.
2. Procure o chamado ou a aprovação do PIM com o mesmo horário e a mesma função.
3. Confira se o resultado foi sucesso. Falha não entra nesta regra.
4. Veja se o alvo já tinha outra função privilegiada antes.
5. Se a ação ocorreu fora da janela de mudança, marque isso no incidente.
6. Não remova a função por conta própria.

## Falsos positivos

Plantão aprovado, elegibilidade PIM já autorizada e função temporária de suporte. A regra não sabe se existiu chamado. Essa checagem é do analista.

## Escalação para o N2

Escale quando não houver aprovação, o ator for incomum ou a função for Global Administrator. Entregue o correlation id, o ator e o alvo.

## Contenção

Remover a função é decisão do N2, com o dono de identidade. O playbook não desativa o usuário. Se o ator também for suspeito, o N2 trata as duas contas.
